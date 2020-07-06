# spike on tls session resumption within a "holo tunnel"

### key

```
c_1 - cipher client bytes received
c_2 - decrypted client bytes received
s_1 - cipher server bytes received
s_2 - decrypted server bytes received
```

### results

```
-- first message --
0: c_1: 0, c_2: 0, s_1: 237, s_2: 0
1: c_1: 709, c_2: 0, s_1: 237, s_2: 0
2: c_1: 709, c_2: 0, s_1: 333, s_2: 0
3: c_1: 902, c_2: 0, s_1: 333, s_2: 10
4: c_1: 902, c_2: 10, s_1: 333, s_2: 10
cli got: srv-to-cli
srv got: cli-to-srv
-- second message --
0: c_1: 0, c_2: 0, s_1: 338, s_2: 0
1: c_1: 210, c_2: 0, s_1: 338, s_2: 0
2: c_1: 210, c_2: 0, s_1: 434, s_2: 0
3: c_1: 403, c_2: 0, s_1: 434, s_2: 10
4: c_1: 403, c_2: 10, s_1: 434, s_2: 10
cli got: srv-to-cli
srv got: cli-to-srv
-- third message --
0: c_1: 0, c_2: 0, s_1: 338, s_2: 0
1: c_1: 210, c_2: 0, s_1: 338, s_2: 0
2: c_1: 210, c_2: 0, s_1: 434, s_2: 0
3: c_1: 403, c_2: 0, s_1: 434, s_2: 10
4: c_1: 403, c_2: 10, s_1: 434, s_2: 10
cli got: srv-to-cli
srv got: cli-to-srv
```

If we remove the ticketing mechanism, we still require the same handshake back-n-forth count, but actually with slightly fewer bytes sent.

As we can see, session resumption does actually save us some bytes sent from server to client.

In terms of acting within light-weight quic channels, however, the back-n-forth count is actually the more problematic...

### David.B's Recommendation

- I think we should proceed with the plan to open a new QUIC BI stream/channel for each message request/response on both sides of the relay/proxy server. We can go ahead and do the full session resumption TLS handshake through this tunnel, and close the channel afterward.
- At a future point when/if we are starting to feel this overhead, we can optimize by NOT closing those channels, and instead maintain them in a pool for any concurrent request/responses we want to run in parallel.
