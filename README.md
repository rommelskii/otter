# Otter Protocol 

branch: auth

This branch is strictly for introducing the authentication functionality instead of 
fetching credentials via CPUSH and CPULL.

## Credential Hashing
The current working implementation of the Otter protocol only accounts for the tethering action. 
The credential transactions, however, are just boilerplates. Recall that the point of the
Otter protocol is to provide client-server tethering and authentication of user details upon
provision in the clientside. 

How can we authenticate user details securely? Obviously, we cannot just use plaintext 
payloads over the network via the usual CPULL, CPUSH, and CINV packets. What we can do, is to
introduce hashing. 

Suppose we have a username-password entry in the serverside otfile `(username123, password123)`. 
Let `hash(str)` take in a string `str` and output an unsigned 64-bit number. Compute the hashes:

```
uname_hash := hash("username123")
psk_hash := hash("password123")
```

Instead of storing these both as their own individual payloads, we can combine the two hashes:

```
final_hash := uname_hash + psk_hash
```

Nice! Now we have some obfuscated form of information that represents the username-password
combination in a way that is not obvious. We can then convert the `final_hash` into a string
and use it as a new `PL_HASH` msgtype to indicate that we are sending over user details to
authenticate if it exists in the server. 

## Authentication Tables

Recall that in the server context, we have a context table for storing client contexts and a 
otfile table that stores the entries from an otfile. Suppose now that we have received a CPULL
containing the PL_HASH payload. How can we then authenticate the hash to our existing otable?

Suppose we create a new table called an authentication table or atable to replace the otable.
The atable is a hash set (keys map to itself) where it contains all the username+password hashes 
for every otfile entry.

For added security, suppose that every regular interval, we generate a randomized 64-bit number
that we add to the hashes before being added to the atable. This is a process known as salting,
where we add a number to the hash itself for more obfuscation. In the event that there is
already an existing atable and rehashing is needed, we just destroy the old atable and create
a new one from the same otfile but with the new hash.

