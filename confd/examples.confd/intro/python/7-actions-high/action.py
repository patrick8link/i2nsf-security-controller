"""
*********************************************************************
* ConfD Actions intro example                                       *
* Implements a couple of actions                                    *
*                                                                   *
* (C) 2017 Tail-f Systems                                           *
* Permission to use this code as a starting point hereby granted    *
*                                                                   *
* See the README file for more information                          *
*********************************************************************
"""
from __future__ import print_function

import sys
from config_ns import ns

import confd
from confd.dp import Action, Daemon
from confd.maapi import Maapi
from confd.log import Log


#logger class used by Daemon
class MyLog(object):
    def info(self, arg):
        print("info: %s" % arg)
    def error(self, arg):
        print("error: %s" % arg)

class RebootAction(Action):
    @Action.action
    def cb_action(self, uinfo, name, kp, input, output):
        self.log.info("reboot")

class RestartAction(Action):
    @Action.action
    def cb_action(self, uinfo, name, kp, input, output):
        self.log.info("restart")

        mode_value = str(input.mode)

        # if we get mode_value == error1, we reply with generic error
        if mode_value == "error1":
            return confd.CONFD_ERR

        # if we get mode_value == error2, we reply with specific error
        if mode_value == "error2":
            raise ValueError("myfail")

        # otherwise, we create a result string with mode-result-...
        res = mode_value + "-result"

        if input.debug.exists():
            res = res + "-debug"

        if input.foo.exists():
            res = res + "-foo"
            if input.foo.debug.exists():
                res = res + "-debug-foo"

        output.time = res
        self.log.info(str(output))

class ResetAction(Action):
    @Action.action
    def cb_action(self, uinfo, name, kp, input, output):
        self.log.info("reset")
        when_value = input.when
        res = str(when_value) + "-result"
        output.time = res

# not yet implemented
#class AbortTestAction(Action):
#    @Action.action
#    def cb_action(self, uinfo, name, kp, input, output):
#        self.log.info('responding delayed...')
#        return confd.DELAYED_RESPONSE
#
#    def cb_abort(self, uinfo):
#        self.log.info("Aborting outstanding action")
#        # We need to clean  up the worker socket by replying
#        dp.action_delayed_reply_error(uinfo, "aborted")
#        # - raise exception?


def load_schemas():
    with Maapi():
        pass

if __name__ == "__main__":

    load_schemas()
    logger = Log(MyLog(), add_timestamp=True)
    d = Daemon(name='myactiond', log=logger)

    a = []
    a.append(RebootAction(daemon=d, actionpoint='act-reboot', log=logger))
    a.append(RestartAction(daemon=d, actionpoint='act-restart', log=logger))
    a.append(ResetAction(daemon=d, actionpoint='act-reset', log=logger))
#    a.append(AbortTestAction(daemon=d, actionpoint='act-abort-test',
#        log=logger))

    logger.info('--- Daemon myaction STARTED ---')
    d.start()
    print('Hit <ENTER> to quit')
    sys.stdin.read(1)
    d.finish()
    logger.info('--- Daemon myaction FINISHED ---')
