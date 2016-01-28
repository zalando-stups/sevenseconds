import json
import botocore.exceptions
from ..helper import ActionOnExit, error


def check_policy_simulator(account: object):
    # return
    roles = account.config.get('roles', {})
    checks = account.config.get('roles_simulator', {})
    errorcount = 0
    for rolename, rolechecks in sorted(checks.items()):
        errormsg = run_simulation(account.session, roles, rolename, rolechecks)
        if len(errormsg):
            errorcount += len(errormsg)
            print('\n'.join(errormsg))
    if errorcount:
        # fatal_error('found {} error(s) in the policys. Abort!'.format(errorcount))
        error('found {} error(s) in the policys.'.format(errorcount))


def run_simulation(session, roles, rolename, rolechecks):
    iamc = session.client('iam')
    errormsg = []
    with ActionOnExit('Checking role {rolename}..', **vars()) as act:
        for checkname, checkoptions in sorted(rolechecks.items()):
            try:
                result = iamc.simulate_custom_policy(PolicyInputList=[json.dumps(roles[rolename]['policy'])],
                                                     **checkoptions['simulation_options'])
            except botocore.exceptions.ClientError as e:
                act.fatal_error(e)

            results = result['EvaluationResults']
            while result.get('IsTruncated', False):
                result = iamc.simulate_custom_policy(Marker=result['Marker'],
                                                     PolicyInputList=[json.dumps(roles[rolename]['policy'])],
                                                     **checkoptions['simulation_options'])
                results.extend(result['EvaluationResults'])
            for result in results:
                if result['EvalDecision'] != checkoptions['simulation_result']:
                    errormsg.append('[{}] {} is {} and NOT {}'.format(checkname,
                                                                      result['EvalActionName'],
                                                                      result['EvalDecision'],
                                                                      checkoptions['simulation_result']))
        if len(errormsg):
            act.error('missmatch')
    return errormsg
