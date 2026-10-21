"""Write internal/decode/awscli.json.gz from awscli's own command table.

The AWS API MCP server parses call_aws commands with awscli v1, so the
table follows the same parser: CLI service and operation names, the API
operation each runs (null for awscli customizations), and, for the services
catalog/aws has rules for, each operation's HTTP binding and the API member,
type and wire location behind every CLI argument.

    python3 -m venv /tmp/v && /tmp/v/bin/pip install awscli==1.46.0
    /tmp/v/bin/python tools/awscligen/gen.py internal/decode/awscli.json.gz
"""
import gzip
import json
import sys

import awscli
import botocore
from awscli.arguments import BooleanArgument
from awscli.clidriver import ServiceCommand, create_clidriver

# Signing names of the services catalog/aws has rules for.
DETAILED = {"cloudformation", "dynamodb", "ec2", "iam", "kms", "lambda", "rds",
            "route53", "s3", "secretsmanager", "ssm", "sts"}


def arg_entry(arg):
    model = getattr(arg, "argument_model", None)
    member = getattr(arg, "_serialized_name", None)
    if model is None or not member:
        # Arguments awscli adds that are not API members: --cli-input-json
        # supplies parameters Opfence cannot see, --generate-cli-skeleton
        # takes an optional value. "u" marks them unread.
        e = {"u": True}
        nargs = getattr(arg, "nargs", None)
        if nargs == "?":
            e["opt"] = True
        elif getattr(arg, "cli_type_name", None) == "boolean" or getattr(arg, "_action", None) in ("store_true", "store_false"):
            e["flag"] = True
        return e
    e = {"m": member, "t": model.type_name}
    ser = model.serialization or {}
    if ser.get("location"):
        e["l"] = ser["location"]
    if ser.get("name") and ser.get("name") != member:
        e["ln"] = ser["name"]
    if ser.get("queryName"):
        e["qn"] = ser["queryName"]
    if model.type_name == "list":
        if ser.get("flattened"):
            e["fl"] = True
        e["mt"] = model.member.type_name
    if isinstance(arg, BooleanArgument) and arg.name.startswith("no-"):
        e["neg"] = True
    return e


def main(out_path):
    driver = create_clidriver()
    services = {}
    for name, cmd in sorted(driver._get_command_table().items()):
        if not isinstance(cmd, ServiceCommand):
            continue
        try:
            sm = cmd.service_model
        except Exception:  # a service whose model fails to load
            continue
        meta = sm.metadata
        svc = {"signing": sm.signing_name, "protocol": meta.get("protocol"), "ops": {}}
        if meta.get("apiVersion"):
            svc["version"] = meta["apiVersion"]
        if meta.get("targetPrefix"):
            svc["target"] = meta["targetPrefix"]
        if meta.get("jsonVersion"):
            svc["json"] = meta["jsonVersion"]
        detailed = sm.signing_name in DETAILED
        details = {}
        for opname, opcmd in sorted(cmd._get_command_table().items()):
            om = getattr(opcmd, "_operation_model", None)
            if om is None:
                svc["ops"][opname] = None  # an awscli customization
                continue
            svc["ops"][opname] = om.name
            if not detailed:
                continue
            args = {}
            for an, arg in sorted(opcmd.arg_table.items()):
                if getattr(arg, "positional_arg", False):
                    continue
                args[an] = arg_entry(arg)
            http = om.http or {}
            details[opname] = {"method": http.get("method", "POST"), "uri": http.get("requestUri", "/"), "args": args}
        if details:
            svc["detail"] = details
        services[name] = svc
    doc = {"awscli": awscli.__version__, "botocore": botocore.__version__, "services": services}
    data = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    with open(out_path, "wb") as f:
        f.write(gzip.compress(data, mtime=0))
    ops = sum(len(s["ops"]) for s in services.values())
    print(f"{len(services)} services, {ops} operations, {len(data)} bytes ({awscli.__version__})")


if __name__ == "__main__":
    main(sys.argv[1])
