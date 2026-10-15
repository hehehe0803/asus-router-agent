"""Public parental approval intent must survive output selection intact."""
from router_agent.output import envelope


def test_selected_plan_preserves_review_and_explicit_schedule_without_private_context():
    plan = {
        'operation': 'parental.rule',
        'before': {'policy_fingerprint': 'a' * 64},
        'after': {'policy_fingerprint': 'b' * 64},
        'review': {
            'before': {'alias': 'client-' + '1' * 16, 'rule_type': 'time',
                       'name_fingerprint': 'c' * 64, 'schedule_fingerprint': 'd' * 64,
                       'schedule_present': True},
            'after': None,
            'preservation': 'Unrelated rules remain unchanged.',
        },
        'intent': {'action': 'rule', 'client_alias': 'client-' + '1' * 16,
                   'rule_type': 'time', 'schedule': 'W03E21000700'},
        'side_effects': ['firewall_restart', 'schedule_semantics_and_timezone_unverified'],
        'context_binding': 'e' * 64,
    }
    selected = envelope({'plan': {**plan, 'private_context': {'MULTIFILTER_DEVICENAME': 'private-name'},
                                         'password': 'private-password'}})
    assert selected['data']['plan'] == plan


def test_all_clients_toggle_review_survives_selection():
    review = {'enabled': True, 'block_all': False, 'rule_count': 3,
              'rules_write_recoverable': False}
    value = {'intent': {'action': 'block_all', 'blocked': True},
             'review': {'before': review, 'after': {**review, 'block_all': True}},
             'side_effects': ['firewall_restart', 'all_clients_internet_access']}
    assert envelope(value)['data'] == value


def test_failure_metadata_keeps_bounded_codes_and_scrubs_corrupted_state():
    assert envelope({'failure_code':'timeout','failure_stage':'write','verification_failure_code':'state_mismatch','verification_failure_stage':'verify'})['data'] == {'failure_code':'timeout','failure_stage':'write','verification_failure_code':'state_mismatch','verification_failure_stage':'verify'}
    selected = envelope({'failure_code':'private-password','failure_stage':'private-token','verification_failure_code':{'message':'private-secret'},'verification_failure_stage':'private-host'})['data']
    assert selected == {'failure_code':'write_failed','failure_stage':'write','verification_failure_code':'verification_read_failed','verification_failure_stage':'verify'}
