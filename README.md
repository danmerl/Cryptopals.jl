# Cryptopals.jl
Jupyter notebooks for the Cryptopals challenges, in Julia

Someone at work mentioned something called the "cryptopals challenges", and I
got it into my head that working through these challenges in Julia would be a
fun way to spend some nights and weekends.  This repo chronicles these efforts.

The challenges are described here: http://cryptopals.com/.

Each notebook, at least as of the time of this writing, is intentionally self
contained, copy pasta be damned. Sorry.  However, the file `cryptofuncs.jl`
is mostly a master file of the collected utility functions implemented across
the notebooks. At some point, as the notebooks become lengthier, this will be
included at the expense of readability. Such is life.

Also, I'm committing each notebook cleared of all output, because the thrill of
hitting return and seeing some ciphertext jibber jabber rendered into plaintext
is really the whole reason to do this, right?  So clone the workbooks and step
through them if you like, but far be it for me to spill the beans on the secret
messages. There's enough disappointment in the world.

Also also, I'm not including in this repo the numbered files downloadable from
cryptopals.com (e.g. `4.txt`, `6.txt`, `7.txt` &c) because those are their files
and I don't know what license they had intended for them.  So I guess contrary to
the claim above, these notebooks aren't so self contained after all.  Refer to
the previous thing about disappointment.
