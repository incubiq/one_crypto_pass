## ocp_auth

AUTH_ALICE={
    "mnemonic": "drastic churn pottery such common lawsuit grass join file tobacco quantum dentist satisfy junk utility",
    "seed": "4f16c8c5f818aa05dd425ae8e1f269780691b853234a11372c876de7b3448fa3c0b4b81371f1e75ff6502996fdbdbfbb69a613c620172d72ff8602c7d2b36e74",
    "addr": "addr_test1qpseam5yw9yq6lpvev4lpv7cjnd79n740ul8ktlggffa5aq3pn85twq2wsctps9v7swhq7nv5ckuxaezf29pfeqdy5hs5xqkfk",
    "private": "ed25519e_sk1epgkgh6kysctm3tsum2rzl4v07yfmd5qmdtnjygtt5jajkf35pq9hmulagey0src3mjl0haww9mg98pf59zwy25fsmyp4fz4a0nfnsqa0004z",    
    "name": "Alice",
    "did": "did:peer:12345"
}

AUTH_BOB={
    "mnemonic": "kiwi palm quiz smooth dentist school able normal purchase pistol purse current fatigue paddle service",
    "seed": "293e238316fac4d9e43719932e0952a7cdaf6b0fa8681a49e40bc4739464f60569a7da757c4575d808ce4b2d483e27b480259aa22eb0ceb3674bfd434706e20b",
    "addr": "addr_test1qry393l8jvjt9tkwmh5ku7qgt4ykh2pwg5tsslsnpatvy7t6rfvlnm8p37l49sjvtqaxqdf5rfd258ahyz70g35ytvss7jwmhm",
    "private": "ed25519e_sk17zk4ma5pr3duhvw4cqpkyqs86datm7cts7cvg7h6nrxfphys7dvz2vl8cvav8vhfvc2kx6lpwfay7a6zqarhph3tyvp4snrmlj2rukqmlsy77",
    "name": "Bob",
    "did": "did:peer:09876"
}

class InMemDB:
    def __init__(self):
        return
        
    def getAlice(self):
        return AUTH_ALICE
    
    def getBob(self):
        return AUTH_BOB
    