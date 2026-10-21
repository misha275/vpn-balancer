package main

// Mode "stable IP": the user stays on one node for as long as it works, so that his exit address changes as rarely as
// possible. The first node is the best one by the usual parameters. After that the node is replaced only when it died,
// left the pool or exits in a forbidden country (the "failover" branch of decideModeLocked); a better or faster node,
// or a quality complaint, never moves it.
