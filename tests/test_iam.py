import pytest
import sevenseconds.config.iam as iam


SAMPLE_ROLES = {
    "Shibboleth-Administrator": {
        "attached_policies": ["arn:aws:iam::aws:policy/AdminDefaultPolicy"],
        "policy": {
            "Statement": [
                {"Effect": "Allow", "Resource": "Test", "Action": "foo:*"},
                {"Effect": "Deny", "Resource": "Test", "Action": "bar:*"},
            ]
        },
    },
    "Shibboleth-PowerUser": {
        "attached_policies": ["arn:aws:iam::aws:policy/PowerUserDefaultPolicy"],
        "policy": {
            "Statement": [
                {"Effect": "Allow", "Resource": "Test", "Action": "baz:*"},
            ]
        },
    },
}

SAMPLE_POLICIES = [
    {
        "role": "Shibboleth-Administrator",
        "statement": {"Effect": "Allow", "Resource": "Additional", "Action": "test:*"},
    },
    {
        "role": "Shibboleth-Administrator",
        "statement": {"Effect": "Deny", "Resource": "Additional", "Action": "abc:*"},
    },
]

SAMPLE_ATTACHED_POLICIES = [
    {
        "role": "Shibboleth-PowerUser",
        "policies": ["arn:aws:iam::aws:policy/PolicyA", "arn:aws:iam::aws:policy/PolicyB"],
    }
]


def test_effective_policies_merge():
    config = {
        "roles": SAMPLE_ROLES,
        "additional_policies": SAMPLE_POLICIES,
    }
    expected = {
        "Shibboleth-Administrator": {
            "attached_policies": ["arn:aws:iam::aws:policy/AdminDefaultPolicy"],
            "policy": {
                "Statement": [
                    {"Effect": "Allow", "Resource": "Test", "Action": "foo:*"},
                    {"Effect": "Deny", "Resource": "Test", "Action": "bar:*"},
                    {"Effect": "Allow", "Resource": "Additional", "Action": "test:*"},
                    {"Effect": "Deny", "Resource": "Additional", "Action": "abc:*"},
                ]
            },
        },
        "Shibboleth-PowerUser": {
            "attached_policies": [
                "arn:aws:iam::aws:policy/PowerUserDefaultPolicy",
            ],
            "policy": {
                "Statement": [
                    {"Effect": "Allow", "Resource": "Test", "Action": "baz:*"},
                ]
            },
        },
    }

    assert expected == iam.effective_roles(config)

    # check that the original config was not affected
    assert 2 == len(config["roles"]["Shibboleth-Administrator"]["policy"]["Statement"])


def test_effective_attached_policies_merge():
    config = {
        "roles": SAMPLE_ROLES,
        "additional_attached_policies": SAMPLE_ATTACHED_POLICIES,
    }
    expected = {
        "Shibboleth-Administrator": [
            "arn:aws:iam::aws:policy/AdminDefaultPolicy",
        ],
        "Shibboleth-PowerUser": [
            "arn:aws:iam::aws:policy/PowerUserDefaultPolicy",
            "arn:aws:iam::aws:policy/PolicyA",
            "arn:aws:iam::aws:policy/PolicyB",
        ],
    }

    for role_name, role_cfg in SAMPLE_ROLES.items():
        assert expected[role_name] == iam.effective_attached_policies(config, role_name, role_cfg)


@pytest.mark.parametrize(
    "roles",
    [
        # Dropped role
        {"Shibboleth-Administrator": {"drop": True}},
        # Missing role
        {
            "Shibboleth-PowerUser": {
                "policy": {
                    "Statement": [
                        {"Effect": "Allow", "Resource": "Test", "Action": "baz:*"},
                    ]
                }
            }
        },
        # No policy
        {"Shibboleth-Administrator": {}},
        # Policy but no statement
        {"Shibboleth-Administrator": {"policy": {}}},
    ],
)
def test_effective_policies_fail_invalid(roles):
    config = {
        "roles": roles,
        "additional_policies": SAMPLE_POLICIES,
    }

    with pytest.raises(ValueError):
        iam.effective_roles(config)
