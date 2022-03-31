from treelib import *

def technique_get_possible_region(technique):
    answer_sheet = {
        "BoundOFlow": ["stack", "heap", "data", "bss"],
        "NBoundOFlow": ["stack", "heap", "data", "bss"],
        "OOBPtrHijack": ["stack", "heap", "data", "bss"],
        "StructOFlow": ["stack", "heap", "data", "bss"],
        "NBoundUFlow": ["stack", "heap", "data", "bss"],
        "PtrHijack": ["stack"],
    }
    return answer_sheet[technique]

def target_get_possible_technique(target):
    answer_sheet = {
        "retaddr": ["BoundOFlow", "NBoundOFlow", "OOBPtrHijack", "PtrHijack"],
        "oldebp": ["BoundOFlow"],
        "GOT": ["OOBPtrHijack", "PtrHijack"],
        "funcptr": ["BoundOFlow", "NBoundOFlow", "OOBPtrHijack", "PtrHijack", "StructOFlow", "NBoundUFlow"],
        "hook": ["OOBPtrHijack", "PtrHijack"],
        "exit": ["OOBPtrHijack", "PtrHijack"],
        "jmpbuf": ["NBoundOFlow","OOBPtrHijack", "PtrHijack"]
    }
    return answer_sheet[target]

def function_get_possible_parent(function):
    # all functions are compatible
    pass

def testcase_getlist(attr_regions, attr_techniques, attr_targets, attr_functions):
    tree = Tree()
    tree.create_node("RecIPE", "root")
    # first create subtree for each region
    for each_region in attr_regions:
        tree.create_node(each_region, each_region, parent="root")

    # then choose possible region for each technique
    for each_technique in attr_techniques:
        parent_list = technique_get_possible_region(each_technique)
        for each_parent in parent_list:
            tag = each_technique
            identifier = "{}_{}".format(each_parent, each_technique)
            tree.create_node(tag, identifier, parent=each_parent)

    # then choose possible region for each technique
    for each_leaf in tree.leaves():
        if tree.depth(each_leaf)!=2:
            continue
        for each_target in attr_targets:
            if each_target=="oldebp" and "stack" not in each_leaf.identifier: continue
            if each_target=="retaddr" and "stack" not in each_leaf.identifier: continue
            if each_target=="jmpbuf" and "stack" not in each_leaf.identifier: continue
            parent_list = target_get_possible_technique(each_target)
            if each_leaf.identifier.split("_")[-1] in parent_list:
                tag = each_target
                identifier = "{}_{}".format(each_leaf.identifier, each_target)
                tree.create_node(tag, identifier, parent=each_leaf.identifier)

    # finally combine them with four functions
    for each_leaf in tree.leaves():
        if tree.depth(each_leaf)!=3:
            continue
        for each_function in attr_functions:
            tag = each_function
            identifier = "{}_{}".format(each_leaf.identifier, each_function)
            tree.create_node(tag, identifier, parent=each_leaf.identifier)

    # visualize the test case tree
    # tree.to_graphviz()
    # tree.save2file("./TestGen.tree")

    testcase_list = []
    for each_leaf in tree.leaves():
        if tree.depth(each_leaf)!=4:
            continue
        testcase_list.append(each_leaf.identifier)
    return testcase_list