#!/usr/bin/env python

import sys
import json
import yaml


def cfn_constructor(loader, node):
    if isinstance(node, yaml.ScalarNode):
        fields = loader.construct_scalar(node)
    elif isinstance(node, yaml.MappingNode):
        fields = loader.construct_mapping(node)
    elif isinstance(node, yaml.SequenceNode):
        fields = loader.construct_sequence(node)
    return repr((node.tag, fields))


class Equals(yaml.YAMLObject):
    yaml_tag = u"!Equals"

    def __init__(self, *args):
        self.args = args

    def __repr__(self):
        return repr(self.args)


template_yaml = sys.stdin.read()

for tag in ["Ref", "GetAtt", "Equals", "Sub", "Select", "If"]:
    yaml.add_constructor("!%s" % tag, cfn_constructor)

template = yaml.load(template_yaml)
resources = template["Resources"]
rsrc_names = list(resources.keys())
dependencies = dict([(name, []) for name in rsrc_names])

for name, body in resources.iteritems():
    body_json = json.dumps(body)
    for name2 in rsrc_names:
        if name == name2:
            continue
        else:
            if name2 in body_json:
                dependencies[name].append(name2)

dep_list = [
    "%s %s" % (rsrc, dep)
    for rsrc, deps in dependencies.iteritems() for dep in deps
]

print "\n".join(dep_list)
