# Artefact
+ `artefact/`: the resources (mostly log file) to help validate our claims
  + `v1-bypass.txt` and `v2-pfitzmann.txt`: the output produced by our experiment on a local cascade for each attack; uses *server* (latest commit [058d0af9](https://git.xx.network/elixxir/server/-/tree/058d0af993561b8cde4979caf87037697959f595))
  + `v3v4/`
    + `client.log`: log file produced with the compiled *client* library v4.7.5 (commit 0c3e5a3c), records output of a user during an E2E private chat session. The client library was only lightly patched to add logging for message structure, and hence not included in the artefact
    + `ndf.json`: Network definition file, which shows 348 nodes in the network

## V1 Insider Attack
The log shows a succeeded insider attack on a test batch. By searching for `[Insider]` keyword, one can find the batch decrypted by the malicious last node during the real-time re-ecnryption/decryption phase.

By executing the bypassing attack, only the adversary's permutation is included in the batch decryption key, and the attacker used identity permutation. Therefore, we observe the output batch to retain the same order as the input batch

```
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[0]=1 in GRP: 8yU7MTm4o/...
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[1]=2 in GRP: 8yU7MTm4o/...
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[2]=3 in GRP: 8yU7MTm4o/...
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[3]=4 in GRP: 8yU7MTm4o/...
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[4]=5 in GRP: 8yU7MTm4o/...
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[5]=6 in GRP: 8yU7MTm4o/...
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[6]=7 in GRP: 8yU7MTm4o/...
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[7]=8 in GRP: 8yU7MTm4o/...
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[8]=9 in GRP: 8yU7MTm4o/...
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[9]=a in GRP: 8yU7MTm4o/...
DEBUG 2025/08/05 17:16:21 [Insider] real-time re-encrypt, slot[10]=b in GRP: 8yU7MTm4o/..
...
```

## V2 Pfitzmann Attack
The log shows a successfull Pfitzmann attack on a test batch. By searching for `[Pfitzmann]` keyword, one can find the linked message recovered from the output batch compared to the expected output

```
DEBUG 2025/08/05 17:18:10 [Pfitzmann] found linked messages: 4->3, 6->8, 5->18, 7->2
DEBUG 2025/08/05 17:18:10 [Pfitzmann] expected linked messages: 4->3, 5->18, 6->8, 7->2
PASS
```

The algorithm for computing the linked message runs with the following arguments: the tagged slot `tagSlot`, the exponents `E`, and the target slots `targetSlots`. It searches for unique slots $(a,b,c,d)$ such that $m_a^{E[0]} \cdot m_b^{E[1]} \cdot m_c^{E[2]} = m_d$. 

Note that the formula should change to $m_a^{E[0]} \cdot m_b^{E[1]} \cdot m_c^{E[2]} \cdot m_{tag} = m_d$ if we did not set the original plaintext ($ m_{tag}$) of the tagged slot to $1$.

```
targetSlots := []uint32{4, 5, 6}
tagSlot := uint32(7)
E := []int{43, 56, 67}
idxs := []int{0, 1, 2}
perms := permutations(idxs)
foundDup := false
expected := []uint32{permutationMapping[targetSlots[0]], permutationMapping[targetSlots[1]], permutationMapping[targetSlots[2]], permutationMapping[tagSlot]}
loop:
for a := 0; a < len(completedBatch.Slots); a++ {
	for b := a + 1; b < len(completedBatch.Slots); b++ {
		for c := b + 1; c < len(completedBatch.Slots); c++ {
			for _, perm := range perms {
				tmp := grp.NewInt(1)
				out := grp.NewInt(1)
				grp.Exp(grp.NewIntFromBytes(completedBatch.Slots[a].PayloadA), grp.NewInt(int64(E[perm[0]])), tmp)
				grp.Mul(tmp, out, out)
				grp.Exp(grp.NewIntFromBytes(completedBatch.Slots[b].PayloadA), grp.NewInt(int64(E[perm[1]])), tmp)
				grp.Mul(tmp, out, out)
				grp.Exp(grp.NewIntFromBytes(completedBatch.Slots[c].PayloadA), grp.NewInt(int64(E[perm[2]])), tmp)
				grp.Mul(tmp, out, out)
				for d := 0; d < len(completedBatch.Slots); d++ {
					if grp.NewIntFromBytes(completedBatch.Slots[d].PayloadA).Cmp(out) == 0 {
						foundDup = true
						jww.DEBUG.Printf("[Pfitzmann] found linked messages: %d->%d, %d->%d, %d->%d, %d->%d\n",
							targetSlots[perm[0]], a,
							targetSlots[perm[1]], b,
							targetSlots[perm[2]], c,
							tagSlot, d)

						break loop
					}
				}
			}
		}
	}
}
```

## V3 Tagging Attack
In `artefact/v3v4/client.log`, we can validate that every message (search with "Test msg raw") has a static version byte 0x00 right after the 32-byte key fingerprint, e.g.,
```
c7dc9221cb2821fed34c88a78a8467bf6e943c2023265702e70bf90943c9b0b2 00
47dc9221cb2821fed34c88a78a8467bf6e943c2023265702e70bf90943c9b0b2 00
```

## V4 Resend Attack
In `artefact/v3v4/client.log`, we can observe messages with identical key fingerprint or sih field due to the flawed resend logic, where
```
fp = 47dc9221cb2821fed34c88a78a8467bf6e943c2023265702e70bf90943c9b0b2
sih = 2cfc3d28f20236fa9f983d2274b40ec0c16140aedb14e46f2b
```

## V5 Group vulnerabilities
The exact log for the group attacks demo in the paper was not exported and could no longer be found, and this attack cannot be easily reproduced again as the User Discovery Service for contact establishment in the xx network is down.