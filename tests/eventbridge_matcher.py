"""Local subset of EventBridge event pattern matching, for offline tests.

Supports: exact values, prefix, suffix, anything-but, exists, equals-ignore-case.
Any other operator raises an error, so an unsupported pattern can never pass by accident.
"""

MISSING = object()


def matches(pattern, event):
    """Return True if the event matches the pattern."""
    for key, rule in pattern.items():
        value = event.get(key, MISSING) if isinstance(event, dict) else MISSING
        if isinstance(rule, dict):
            if not isinstance(value, dict) or not matches(rule, value):
                return False
        elif isinstance(rule, list):
            if not _field_matches(rule, value):
                return False
        else:
            raise ValueError("pattern values must be lists or objects: " + repr(key))
    return True


def _field_matches(rules, value):
    # An array in the event matches if any of its elements matches
    values = value if isinstance(value, list) else [value]
    return any(_value_matches(rule, v) for rule in rules for v in values)


def _value_matches(rule, value):
    if not isinstance(rule, dict):
        return value is not MISSING and rule == value
    if len(rule) != 1:
        raise ValueError("one operator per filter: " + repr(rule))
    op, arg = next(iter(rule.items()))
    if op == "exists":
        return (value is not MISSING) == arg
    if value is MISSING:
        return False
    if op == "prefix":
        return isinstance(value, str) and value.startswith(arg)
    if op == "suffix":
        return isinstance(value, str) and value.endswith(arg)
    if op == "equals-ignore-case":
        return isinstance(value, str) and value.lower() == arg.lower()
    if op == "anything-but":
        if isinstance(arg, dict):
            raise NotImplementedError("nested anything-but is not supported: " + repr(arg))
        excluded = arg if isinstance(arg, list) else [arg]
        return value not in excluded
    raise NotImplementedError("operator not supported by the local matcher: " + op)
