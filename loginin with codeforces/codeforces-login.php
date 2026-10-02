<?php
/**
 * Plugin Name: Login with Codeforces
 * Description: 通过 Codeforces OIDC 登录 WordPress（支持 HS256、无 JWKS）+ Rating 排行榜
 * Version:     1.4.0
 * Author:      lizhuoxuan159
 * License:     GPL-2.0-or-later
 * Text Domain: cf-login
 */

if ( ! defined( 'ABSPATH' ) ) exit;

define( 'CF_LOGIN_AUTH_ENDPOINT',  'https://codeforces.com/oauth/authorize' );
define( 'CF_LOGIN_TOKEN_ENDPOINT', 'https://codeforces.com/oauth/token' );

class CF_Login {

    const OPTION_KEY  = 'cf_login_options';
    const META_SUB    = '_cf_login_sub';
    const META_HANDLE = '_cf_login_handle';
    const META_RATING = '_cf_login_rating';
    const META_AVATAR = '_cf_login_avatar';

    private static $instance;

    public static function instance() {
        if ( ! isset( self::$instance ) ) self::$instance = new self();
        return self::$instance;
    }

    private function __construct() {
        add_action( 'admin_menu',         [ $this, 'add_settings_page' ] );
        add_action( 'admin_init',         [ $this, 'register_settings' ] );
        add_action( 'login_form',         [ $this, 'render_login_button' ] );
        add_action( 'tml_login_form_after', [ $this, 'render_login_button' ] ); // 兼容 Theme My Login
        add_action( 'login_footer',       [ $this, 'render_login_error' ] );
        add_action( 'init',               [ $this, 'handle_oauth_flow' ] );
        add_shortcode( 'cf_login_button', [ $this, 'render_shortcode' ] );
        add_shortcode( 'cf_bind_button',  [ $this, 'render_bind_shortcode' ] );
        add_shortcode( 'cf_rating_leaderboard', [ $this, 'render_leaderboard' ] );
        add_action( 'show_user_profile',  [ $this, 'render_bind_button' ] );
        add_action( 'edit_user_profile',  [ $this, 'render_bind_button' ] );
        add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), [ $this, 'action_links' ] );

        // 每日 03:00 自动同步所有已绑定用户的 Rating
        add_action( 'cf_rating_sync_event', [ $this, 'sync_all_cf_ratings' ] );
        if ( ! wp_next_scheduled( 'cf_rating_sync_event' ) ) {
            wp_schedule_event( strtotime( 'tomorrow 03:00' ), 'daily', 'cf_rating_sync_event' );
        }
    }

    /* ---------- 配置 ---------- */

    public function get_options() {
        return wp_parse_args( get_option( self::OPTION_KEY, [] ), [
            'client_id'     => '',
            'client_secret' => '',
            'auto_register' => 1,
            'default_role'  => 'subscriber',
        ] );
    }

    public function get_callback_url() {
        return add_query_arg( 'cf_login_callback', '1', home_url( '/' ) );
    }

    /**
     * 生成授权链接
     * @param string $mode 'login' 或 'bind'
     * @param int    $user_id 绑定模式时的用户 ID
     */
    public function get_auth_url( $mode = 'login', $user_id = 0 ) {
        $opts  = $this->get_options();
        $state = wp_generate_password( 32, false, false );

        // 绑定模式回来源页；登录模式也回来源页，但过滤掉登录页本身
        $referer = wp_get_referer();
        if ( ! $referer || strpos( $referer, 'wp-login.php' ) !== false ) {
            $referer = home_url( '/' );
        }

        $state_data = [
            'redirect' => $referer,
            'mode'     => $mode,
            'user_id'  => $user_id,
        ];
        set_transient( 'cf_login_state_' . $state, $state_data, 600 );

        return add_query_arg( [
            'client_id'     => $opts['client_id'],
            'redirect_uri'  => $this->get_callback_url(),
            'response_type' => 'code',
            'scope'         => 'openid',
            'state'         => $state,
        ], CF_LOGIN_AUTH_ENDPOINT );
    }

    /* ---------- 流程入口 ---------- */

    public function handle_oauth_flow() {
        // 登录按钮
        if ( isset( $_GET['cf_login'] ) && '1' === $_GET['cf_login'] ) {
            if ( empty( $this->get_options()['client_id'] ) ) {
                wp_die( 'Codeforces 登录尚未配置。' );
            }
            wp_redirect( $this->get_auth_url( 'login' ) );
            exit;
        }

        // 绑定按钮
        if ( isset( $_GET['cf_bind'] ) && '1' === $_GET['cf_bind'] ) {
            if ( ! is_user_logged_in() ) {
                wp_die( '请先登录 WordPress 账号再进行绑定。' );
            }
            wp_redirect( $this->get_auth_url( 'bind', get_current_user_id() ) );
            exit;
        }

        // CF 回调
        if ( isset( $_GET['cf_login_callback'] ) && '1' === $_GET['cf_login_callback'] ) {
            $this->handle_callback();
        }
    }

    private function handle_callback() {
        if ( isset( $_GET['error'] ) ) {
            $this->redirect_error( sanitize_text_field( $_GET['error'] ) );
        }

        if ( empty( $_GET['code'] ) || empty( $_GET['state'] ) ) {
            $this->redirect_error( 'missing_code_or_state' );
        }

        $state = sanitize_text_field( $_GET['state'] );
        $state_data = get_transient( 'cf_login_state_' . $state );
        if ( false === $state_data ) {
            $this->redirect_error( 'invalid_state' );
        }
        delete_transient( 'cf_login_state_' . $state );

        // 用 code 换 token
        $tokens = $this->exchange_code( sanitize_text_field( $_GET['code'] ) );
        if ( is_wp_error( $tokens ) ) {
            $this->redirect_error( $tokens->get_error_message() );
        }
        if ( empty( $tokens['id_token'] ) ) {
            $this->redirect_error( 'no_id_token' );
        }

        // 验证并解析 ID Token
        $claims = $this->verify_id_token( $tokens['id_token'] );
        if ( is_wp_error( $claims ) ) {
            $this->redirect_error( $claims->get_error_message() );
        }

        $redirect_to = $state_data['redirect'] ?? home_url( '/' );
        $mode        = $state_data['mode'] ?? 'login';

        if ( $mode === 'bind' ) {
            $this->do_bind( intval( $state_data['user_id'] ), $claims, $redirect_to );
        } else {
            // 登录模式
            $user = $this->find_or_create_user( $claims );
            if ( is_wp_error( $user ) ) {
                $this->redirect_error( $user->get_error_message() );
            }
            wp_set_current_user( $user->ID );
            wp_set_auth_cookie( $user->ID, true );
            do_action( 'wp_login', $user->user_login, $user );

            // 管理员直接进后台；其他用户回来源页
            if ( user_can( $user, 'manage_options' ) ) {
                $redirect_to = admin_url();
            }

            wp_safe_redirect( $redirect_to );
            exit;
        }
    }

    /* ---------- 绑定逻辑 ---------- */

    private function do_bind( $user_id, $claims, $redirect ) {
        $user = get_user_by( 'id', $user_id );
        if ( ! $user ) {
            $this->redirect_error( 'user_not_found' );
        }

        // 检查此 CF 账号是否已被其他用户绑定
        $existing = get_users( [
            'meta_key'    => self::META_SUB,
            'meta_value'  => $claims['sub'],
            'number'      => 1,
            'count_total' => false,
            'exclude'     => [ $user_id ],
        ] );
        if ( ! empty( $existing ) ) {
            $this->redirect_error( 'cf_already_bound' );
        }

        update_user_meta( $user_id, self::META_SUB, $claims['sub'] );
        $this->sync_meta( $user_id, $claims );

        wp_safe_redirect( add_query_arg( 'cf_bound', '1', $redirect ) );
        exit;
    }

    /* ---------- Token 交换 ---------- */

    private function exchange_code( $code ) {
        $opts = $this->get_options();

        $response = wp_remote_post( CF_LOGIN_TOKEN_ENDPOINT, [
            'timeout' => 20,
            'headers' => [
                'Accept'       => 'application/json',
                'Content-Type' => 'application/x-www-form-urlencoded',
            ],
            'body' => [
                'grant_type'    => 'authorization_code',
                'code'          => $code,
                'redirect_uri'  => $this->get_callback_url(),
                'client_id'     => $opts['client_id'],
                'client_secret' => $opts['client_secret'],
            ],
        ] );

        if ( is_wp_error( $response ) ) return $response;

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( ! is_array( $data ) ) {
            return new WP_Error( 'token_parse_error', '无法解析 token 响应' );
        }
        if ( isset( $data['error'] ) ) {
            return new WP_Error( 'token_error', $data['error_description'] ?? $data['error'] );
        }
        return $data;
    }

    /* ---------- 验证 HS256 ID Token ---------- */

    private function verify_id_token( $id_token ) {
        $parts = explode( '.', $id_token );
        if ( count( $parts ) !== 3 ) {
            return new WP_Error( 'invalid_jwt', 'JWT 格式无效' );
        }
        list( $h64, $p64, $s64 ) = $parts;

        $header  = json_decode( $this->b64url_decode( $h64 ), true );
        $payload = json_decode( $this->b64url_decode( $p64 ), true );

        if ( ! $header || ! $payload ) {
            return new WP_Error( 'invalid_jwt', '无法解码 JWT' );
        }

        if ( empty( $header['alg'] ) || 'HS256' !== $header['alg'] ) {
            return new WP_Error( 'unsupported_alg', '不支持的签名算法：' . ( $header['alg'] ?? 'null' ) );
        }

        // 用 client_secret 做 HMAC 验证
        $opts   = $this->get_options();
        $expect = $this->b64url_encode(
            hash_hmac( 'sha256', $h64 . '.' . $p64, $opts['client_secret'], true )
        );

        if ( ! hash_equals( $expect, $s64 ) ) {
            return new WP_Error( 'invalid_signature', 'JWT 签名验证失败' );
        }

        $now = time();
        if ( isset( $payload['exp'] ) && $now >= $payload['exp'] ) {
            return new WP_Error( 'token_expired', 'ID Token 已过期' );
        }
        if ( isset( $payload['iat'] ) && $payload['iat'] > $now + 60 ) {
            return new WP_Error( 'invalid_iat', 'ID Token 签发时间异常' );
        }
        if ( isset( $payload['iss'] ) && 'https://codeforces.com' !== $payload['iss'] ) {
            return new WP_Error( 'invalid_issuer', 'Issuer 无效' );
        }
        if ( empty( $payload['sub'] ) ) {
            return new WP_Error( 'missing_sub', 'ID Token 缺少 sub' );
        }

        return $payload;
    }

    /* ---------- 用户查找 / 创建 ---------- */

    private function find_or_create_user( $claims ) {
        $users = get_users( [
            'meta_key'    => self::META_SUB,
            'meta_value'  => $claims['sub'],
            'number'      => 1,
            'count_total' => false,
        ] );

        if ( ! empty( $users ) ) {
            $this->sync_meta( $users[0]->ID, $claims );
            return $users[0];
        }

        $opts = $this->get_options();
        if ( empty( $opts['auto_register'] ) ) {
            return new WP_Error( 'user_not_found', '账号未绑定，请先登录 WordPress 后到个人资料页绑定 Codeforces。' );
        }

        $handle     = ! empty( $claims['handle'] ) ? $claims['handle'] : 'cf_' . substr( $claims['sub'], 0, 8 );
        $user_login = sanitize_user( $handle, true );
        if ( empty( $user_login ) ) {
            $user_login = 'cf_' . wp_generate_password( 8, false, false );
        }
        $user_login = $this->unique_username( $user_login );

        $user_id = wp_insert_user( [
            'user_login'   => $user_login,
            'user_email'   => $user_login . '@cf-login.invalid',
            'user_pass'    => wp_generate_password( 32, true, true ),
            'display_name' => $handle,
            'role'         => $opts['default_role'],
        ] );

        if ( is_wp_error( $user_id ) ) return $user_id;

        update_user_meta( $user_id, self::META_SUB, $claims['sub'] );
        $this->sync_meta( $user_id, $claims );

        return get_user_by( 'id', $user_id );
    }

    private function sync_meta( $user_id, $claims ) {
        if ( isset( $claims['handle'] ) ) update_user_meta( $user_id, self::META_HANDLE, sanitize_text_field( $claims['handle'] ) );
        if ( isset( $claims['rating'] ) ) update_user_meta( $user_id, self::META_RATING, intval( $claims['rating'] ) );
        if ( isset( $claims['avatar'] ) ) update_user_meta( $user_id, self::META_AVATAR, esc_url_raw( $claims['avatar'] ) );
    }

    private function unique_username( $login ) {
        $base = $login;
        $i    = 1;
        while ( username_exists( $login ) ) {
            $login = $base . '_' . $i++;
            if ( $i > 9999 ) {
                $login = $base . '_' . wp_generate_password( 6, false, false );
                break;
            }
        }
        return $login;
    }

    /* ---------- 每日同步所有已绑定用户的 Rating ---------- */

    public function sync_all_cf_ratings() {
        $users = get_users( [
            'meta_key'    => self::META_SUB,
            'number'      => 500,
            'count_total' => false,
        ] );
        if ( empty( $users ) ) return;

        // 建立 handle → user_id 映射
        $handles = [];
        foreach ( $users as $u ) {
            $h = get_user_meta( $u->ID, self::META_HANDLE, true );
            if ( $h ) $handles[ $h ] = $u->ID;
        }
        if ( empty( $handles ) ) return;

        // CF 的 user.info 支持一次查询多个 handle，分批保守处理
        foreach ( array_chunk( array_keys( $handles ), 100 ) as $chunk ) {
            $url  = 'https://codeforces.com/api/user.info?handles=' . implode( ';', $chunk );
            $resp = wp_remote_get( $url, [ 'timeout' => 20 ] );
            if ( is_wp_error( $resp ) ) continue;

            $data = json_decode( wp_remote_retrieve_body( $resp ), true );
            if ( empty( $data['status'] ) || 'OK' !== $data['status'] ) continue;

            foreach ( $data['result'] as $info ) {
                $handle = $info['handle'];
                if ( ! isset( $handles[ $handle ] ) ) continue;
                $uid = $handles[ $handle ];
                update_user_meta( $uid, self::META_RATING, intval( $info['rating'] ?? 0 ) );
                if ( ! empty( $info['avatar'] ) ) {
                    update_user_meta( $uid, self::META_AVATAR, esc_url_raw( $info['avatar'] ) );
                }
            }
        }

        update_option( 'cf_rating_last_sync', time() );
    }

    /* ---------- Rating 排行榜短代码 ---------- */

    public function render_leaderboard( $atts ) {
        $atts = shortcode_atts( [ 'limit' => 50 ], $atts );

        $users = get_users( [
            'meta_key'    => self::META_SUB,
            'number'      => intval( $atts['limit'] ),
            'count_total' => false,
        ] );

        if ( empty( $users ) ) return '<p>暂无用户绑定 Codeforces。</p>';

        $rows = [];
        foreach ( $users as $u ) {
            $rating = intval( get_user_meta( $u->ID, self::META_RATING, true ) );
            if ( $rating <= 0 ) continue;
            $rows[] = [
                'handle' => get_user_meta( $u->ID, self::META_HANDLE, true ),
                'rating' => $rating,
                'avatar' => get_user_meta( $u->ID, self::META_AVATAR, true ),
                'name'   => $u->display_name,
            ];
        }
        if ( empty( $rows ) ) return '<p>暂无 Rating 数据。</p>';

        usort( $rows, fn( $a, $b ) => $b['rating'] - $a['rating'] );

        // CF 段位颜色
        $rank_color = function( $r ) {
            if ( $r >= 3000 ) return '#aa0000';
            if ( $r >= 2600 ) return '#ff0000';
            if ( $r >= 2400 ) return '#ff8c00';
            if ( $r >= 2200 ) return '#ffcc00';
            if ( $r >= 1900 ) return '#aa00aa';
            if ( $r >= 1600 ) return '#0000ff';
            if ( $r >= 1400 ) return '#03a89e';
            if ( $r >= 1200 ) return '#008000';
            return '#808080';
        };

        $last_sync = get_option( 'cf_rating_last_sync' );
        $last_str  = $last_sync ? date( 'Y-m-d H:i', $last_sync ) : '尚未同步';

        ob_start(); ?>
        <div class="cf-leaderboard" style="font-family:-apple-system,sans-serif;">
            <table style="width:100%;border-collapse:collapse;border-radius:8px;overflow:hidden;background:#fff;">
                <thead>
                    <tr style="background:#f5f5f7;border-bottom:2px solid #e5e5ea;">
                        <th style="padding:10px;text-align:left;font-weight:600;">#</th>
                        <th style="padding:10px;text-align:left;font-weight:600;">用户</th>
                        <th style="padding:10px;text-align:left;font-weight:600;">Handle</th>
                        <th style="padding:10px;text-align:right;font-weight:600;">Rating</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ( $rows as $i => $r ) : ?>
                    <tr style="border-bottom:1px solid #f0f0f0;">
                        <td style="padding:10px;color:#888;"><?php echo $i + 1; ?></td>
                        <td style="padding:10px;">
                            <?php if ( $r['avatar'] ) : ?>
                                <img src="<?php echo esc_url( $r['avatar'] ); ?>" style="width:24px;height:24px;border-radius:50%;vertical-align:middle;margin-right:8px;" alt="" />
                            <?php endif; ?>
                            <?php echo esc_html( $r['name'] ); ?>
                        </td>
                        <td style="padding:10px;">
                            <a href="https://codeforces.com/profile/<?php echo esc_attr( $r['handle'] ); ?>" target="_blank" rel="noopener" style="color:#1f8acb;text-decoration:none;font-weight:500;">
                                <?php echo esc_html( $r['handle'] ); ?>
                            </a>
                        </td>
                        <td style="padding:10px;text-align:right;font-weight:700;color:<?php echo $rank_color( $r['rating'] ); ?>;">
                            <?php echo $r['rating']; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            <p style="margin-top:10px;color:#999;font-size:12px;">最后同步：<?php echo esc_html( $last_str ); ?> · 每日 03:00 自动刷新</p>
        </div>
        <?php
        return ob_get_clean();
    }

    /* ---------- 工具 ---------- */

    private function b64url_decode( $data ) {
        $r = strlen( $data ) % 4;
        if ( $r ) $data .= str_repeat( '=', 4 - $r );
        return base64_decode( strtr( $data, '-_', '+/' ) );
    }

    private function b64url_encode( $data ) {
        return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
    }

    private function redirect_error( $msg ) {
        wp_safe_redirect( add_query_arg( 'cf_login_error', rawurlencode( $msg ), wp_login_url() ) );
        exit;
    }

    /* ---------- 前端渲染 ---------- */

    public function render_login_button() {
        $opts = $this->get_options();
        if ( empty( $opts['client_id'] ) ) return;
        $url = add_query_arg( 'cf_login', '1', home_url( '/' ) );
        ?>
        <p style="margin-top:16px;text-align:center;">
            <a href="<?php echo esc_url( $url ); ?>"
               style="display:inline-block;padding:8px 16px;background:#1f8acb;color:#fff;border-radius:4px;text-decoration:none;font-weight:600;">
                Codeforces登录
            </a>
        </p>
        <?php
    }

    public function render_bind_button( $user ) {
        $bound = get_user_meta( $user->ID, self::META_SUB, true );
        $url   = add_query_arg( 'cf_bind', '1', home_url( '/' ) );
        ?>
        <h2>Codeforces 账号</h2>
        <table class="form-table">
            <tr>
                <th>绑定状态</th>
                <td>
                    <?php if ( $bound ) : ?>
                        <p style="color:green;">✅ 已绑定</p>
                        <p>Handle: <strong><?php echo esc_html( get_user_meta( $user->ID, self::META_HANDLE, true ) ); ?></strong></p>
                        <p>Rating: <strong><?php echo esc_html( get_user_meta( $user->ID, self::META_RATING, true ) ); ?></strong></p>
                    <?php else : ?>
                        <p style="color:#999;">尚未绑定 Codeforces 账号</p>
                        <a href="<?php echo esc_url( $url ); ?>" class="button button-primary">绑定 Codeforces</a>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
        <?php
    }

    public function render_bind_shortcode( $atts ) {
        if ( ! is_user_logged_in() ) return '';
        $user_id = get_current_user_id();
        $bound   = get_user_meta( $user_id, self::META_SUB, true );
        $url     = add_query_arg( 'cf_bind', '1', home_url( '/' ) );
        if ( $bound ) {
            return '<p>✅ 已绑定 Codeforces 账号：<strong>' . esc_html( get_user_meta( $user_id, self::META_HANDLE, true ) ) . '</strong></p>';
        }
        return sprintf(
            '<a class="cf-bind-button" href="%s" style="display:inline-block;padding:8px 16px;background:#1f8acb;color:#fff;border-radius:4px;text-decoration:none;font-weight:600;">绑定 Codeforces</a>',
            esc_url( $url )
        );
    }

    public function render_login_error() {
        if ( ! empty( $_GET['cf_bound'] ) ) {
            echo '<div style="margin:16px 0;padding:10px 14px;background:#e8f5e9;color:#2e7d32;border-left:4px solid #43a047;border-radius:3px;">✅ Codeforces 绑定成功！</div>';
        }
        if ( empty( $_GET['cf_login_error'] ) ) return;
        $msg_map = [
            'cf_already_bound' => '此 Codeforces 账号已被其他用户绑定。',
            'user_not_found'   => '未找到对应的 WordPress 用户。',
        ];
        $err = sanitize_text_field( $_GET['cf_login_error'] );
        $msg = $msg_map[ $err ] ?? $err;
        printf(
            '<div style="margin:16px 0;padding:10px 14px;background:#fdecea;color:#b71c1c;border-left:4px solid #e53935;border-radius:3px;font-size:14px;">Codeforces 操作失败：%s</div>',
            esc_html( $msg )
        );
    }

    public function render_shortcode( $atts ) {
        $atts = shortcode_atts( [ 'text' => 'Codeforces登录' ], $atts );
        $opts = $this->get_options();
        if ( empty( $opts['client_id'] ) ) return '';

        $url = add_query_arg( 'cf_login', '1', home_url( '/' ) );
        return sprintf(
            '<a class="cf-login-button" href="%s" style="display:inline-block;padding:8px 16px;background:#1f8acb;color:#fff;border-radius:4px;text-decoration:none;font-weight:600;">%s</a>',
            esc_url( $url ),
            esc_html( $atts['text'] )
        );
    }

    /* ---------- 后台设置页 ---------- */

    public function add_settings_page() {
        add_options_page(
            'Login with Codeforces',
            'Login with Codeforces',
            'manage_options',
            'cf-login',
            [ $this, 'render_settings_page' ]
        );
    }

    public function register_settings() {
        register_setting( 'cf_login_group', self::OPTION_KEY, [
            'sanitize_callback' => [ $this, 'sanitize_options' ],
        ] );
    }

    public function sanitize_options( $in ) {
        return [
            'client_id'     => sanitize_text_field( $in['client_id']     ?? '' ),
            'client_secret' => sanitize_text_field( $in['client_secret'] ?? '' ),
            'auto_register' => empty( $in['auto_register'] ) ? 0 : 1,
            'default_role'  => sanitize_key( $in['default_role'] ?? 'subscriber' ),
        ];
    }

    public function render_settings_page() {
        $opts = $this->get_options();
        $cb   = $this->get_callback_url();
        ?>
        <div class="wrap">
            <h1>Login with Codeforces</h1>
            <p>在 <a href="https://codeforces.com/settings/api" target="_blank">Codeforces API 设置</a> 页面创建 OAuth 应用，并将下面的回调地址填入 <strong>Redirect URI</strong>：</p>
            <p><code style="background:#f0f0f1;padding:6px 10px;display:inline-block;"><?php echo esc_html( $cb ); ?></code></p>
            <form method="post" action="options.php">
                <?php settings_fields( 'cf_login_group' ); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label>Client ID</label></th>
                        <td><input type="text" class="regular-text" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[client_id]" value="<?php echo esc_attr( $opts['client_id'] ); ?>" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label>Client Secret</label></th>
                        <td><input type="password" class="regular-text" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[client_secret]" value="<?php echo esc_attr( $opts['client_secret'] ); ?>" autocomplete="new-password" /></td>
                    </tr>
                    <tr>
                        <th scope="row">自动注册</th>
                        <td><label><input type="checkbox" name="<?php echo esc_attr( self::OPTION_KEY ); ?>[auto_register]" value="1" <?php checked( $opts['auto_register'], 1 ); ?> /> 未绑定时自动创建新用户（关闭则只允许已绑定账号登录）</label></td>
                    </tr>
                    <tr>
                        <th scope="row">默认角色</th>
                        <td>
                            <select name="<?php echo esc_attr( self::OPTION_KEY ); ?>[default_role]">
                                <?php
                                foreach ( [ 'subscriber', 'contributor', 'author', 'editor' ] as $role ) {
                                    printf(
                                        '<option value="%s" %s>%s</option>',
                                        esc_attr( $role ),
                                        selected( $opts['default_role'], $role, false ),
                                        esc_html( $role )
                                    );
                                }
                                ?>
                            </select>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
            <hr />
            <h2>使用方式</h2>
            <p>1. 登录页会自动出现 “Codeforces登录” 按钮（兼容 Theme My Login）。</p>
            <p>2. 任意页面可使用短代码：<code>[cf_login_button]</code> 或 <code>[cf_login_button text="用 CF 登录"]</code></p>
            <p>3. 绑定已有账户：在个人资料页点击「绑定 Codeforces」按钮，或使用短代码 <code>[cf_bind_button]</code>。</p>
            <p>4. Rating 排行榜：使用短代码 <code>[cf_rating_leaderboard]</code> 或 <code>[cf_rating_leaderboard limit="20"]</code>。</p>
            <p>5. 管理员登录后自动跳转 <code>wp-admin</code>，普通用户回到来源页。</p>
        </div>
        <?php
    }

    public function action_links( $links ) {
        array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=cf-login' ) ) . '">设置</a>' );
        return $links;
    }
}

CF_Login::instance();