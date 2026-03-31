def summary(preds, map_attack):
    attack_count = sum(1 for p in preds if map_attack(p)!="Normal")
    normal_count = len(preds) - attack_count

    return attack_count, normal_count