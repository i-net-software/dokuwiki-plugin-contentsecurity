<?php
/**
 * DokuWiki Plugin contentsecurity (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  i-net software / Gerry Weißbach <tools@inetsoftware.de>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class action_plugin_contentsecurity extends DokuWiki_Action_Plugin {

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     * @return void
     */
    public function register(Doku_Event_Handler $controller) {
        global $dokuwikiVersion, $JSINFO;
        $JSINFO['nonce'] = md5($dokuwikiVersion);
        $controller->register_hook('ACTION_HEADERS_SEND', 'BEFORE', $this, 'handle_action_headers_send', $JSINFO['nonce'], 3999);
        $controller->register_hook('TPL_METAHEADER_OUTPUT', 'BEFORE', $this, 'handle_tpl_metaheader_output', $JSINFO['nonce'], 3999);
    }

    /**
     * Send Security Values to browser.
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_action_headers_send(Doku_Event &$event, $nonce) {

        $none = "'none'";
        $self = "'self'";
        $selfNonce = "'self' 'nonce-" . $nonce . "'";

        $policies = array(
            'default-src' => $none,
            'script-src' => $selfNonce,
            'style-src' => $selfNonce,
            'connect-src' => $selfNonce,
            'font-src' => $self,
            'img-src' => $self . " data:",
//            'child-src' => $self,
//            'frame-ancestors' => $self,
//            'plugin-types' => $none,
        );

        $headers = array(
            "X-XSS-Protection" => "1; mode=block",
            "X-Frame-Options" => "SAMEORIGIN",
            "X-Content-Type-Options" => "nosniff",
            "Strict-Transport-Security" => "max-age=63072000; includeSubDomains; preload",
            "Content-Security-Policy" => implode('; ', array_map(
                function ($v, $k) { return sprintf("%s %s", $k, $v); },
                $policies,
                array_keys($policies)
            )),
        );

        foreach( $headers as $header => $value ) array_push($event->data, $header . ': ' . $value);
    }

    /**
     * Add nonce to the linkl, style and script tags in html head.
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */
    public function handle_tpl_metaheader_output(Doku_Event &$event, $nonce) {

        foreach( $event->data as $type => &$content ) {

            switch($type) {
                
                case 'style':
                case 'script':
                    foreach( $content as &$style ) {
                        $style['nonce'] = $nonce;
                    }
                    break;
                case 'link':
                    foreach( $content as &$link ) {
                        if ( $link['rel'] == 'stylesheet' ) {
                            $link['nonce'] = $nonce;
                        }
                    }
            }
        }
    }
}

// vim:ts=4:sw=4:et:
