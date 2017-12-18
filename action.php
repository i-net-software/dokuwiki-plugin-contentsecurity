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

       $controller->register_hook('ACTION_HEADERS_SEND', 'FIXME', $this, 'handle_action_headers_send');
       $controller->register_hook('TPL_METAHEADER_OUTPUT', 'FIXME', $this, 'handle_tpl_metaheader_output');
   
    }

    /**
     * [Custom event handler which performs action]
     *
     * @param Doku_Event $event  event object by reference
     * @param mixed      $param  [the parameters passed as fifth argument to register_hook() when this
     *                           handler was registered]
     * @return void
     */

    public function handle_action_headers_send(Doku_Event &$event, $param) {
    }

    public function handle_tpl_metaheader_output(Doku_Event &$event, $param) {
    }

}

// vim:ts=4:sw=4:et:
