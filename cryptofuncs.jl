function englishiness(ptarray::Array{UInt8, 1})
    EnglishFrequencies = Dict( # from http://scottbryce.com/cryptograms/stats.htm
      'e'=>12.51,
      't'=>9.25,
      'a'=>8.04,
      'o'=>7.6,
      'i'=>7.26,
      'n'=>7.09,
      's'=>6.54,
      'r'=>6.12,
      'h'=>5.49,
      'l'=>4.14,
      'd'=>3.99,
      'c'=>3.06,
      'u'=>2.71,
      'm'=>2.53,
      'f'=>2.3,
      'p'=>2.0,
      'g'=>1.96,
      'w'=>1.92,
      'y'=>1.73,
      'b'=>1.54,
      'v'=>0.99,
      'k'=>0.67,
      'x'=>0.19,
      'j'=>0.16,
      'q'=>0.11,
      'z'=>0.09,
    )
    s=0
    for ll in ptarray
        llchar = Char(ll)
        if isalpha(llchar)
            s+=get(EnglishFrequencies, lowercase(llchar), -5)
        else
            s+=-30
        end
    end
    return s
end

function genBestSingleByteXORDecrypt(ctbytes::Array{UInt8, 1})
    bestdecrypt = []
    bestscore = -Inf
    bestkey = 0x00
    for xx in 0x00:0xff
        if isascii(Char(xx))
            ptbytes = ctbytes $ xx
            ptscore = englishiness(ptbytes)
            if ptscore > bestscore
                bestscore = ptscore
                bestdecrypt = ptbytes
                bestkey = xx
            end
        end
    end
    return (bestscore, bestdecrypt, bestkey)
end

# from challenge 5
function stringToBytes(X::String)
    return [UInt8(X[ii]) for ii in 1:length(X)]
end;

function repeatToLength(a::Array{UInt8,1}, len::Int64)
    if len < length(a)
        return a[1:len]
    else
        b = repeat(a, outer=convert(Int64, ceil(len / length(a))))
        return b[1:len]
    end
end

function repeatingKeyXOR(pt::Array{UInt8,1}, key::Array{UInt8,1})
    return pt $ repeatToLength(key, length(pt))
end

function repeatingKeyXOR(pt::String, key::String)
    return repeatingKeyXOR(stringToBytes(pt), stringToBytes(key))
end

# from challenge 6
function hammingDistance(a::Array{UInt8,1}, b::Array{UInt8,1})
    differentbits = a $ b
    d = 0
    for ii in 1:length(differentbits)
        c = bits(differentbits[ii])
        for jj in 1:8
            if c[jj] == '1'
                d+=1
            end
        end
    end
    return d
end

function hammingDistance(a::String, b::String)
    return hammingDistance(stringToBytes(a), stringToBytes(b))
end;

# from challenge 7
function decryptAES128ECBFileWithKey(fname, key)
    decrypt = chomp(readstring(`openssl enc -d -a -aes-128-ecb -K $key -in $fname`))
    return decrypt
end

# from challenge 9
  function padToNBytes(a::Array{UInt8,1}, nbytes)
      newa = Array{UInt8,1}(nbytes)
      ntopad = nbytes - length(a)
      newa[1:length(a)] = a
      newa[(length(a)+1):nbytes] = UInt8(ntopad)
      return newa
  end

  function padToNBytes(a::String, nbytes)
      return String(padToNBytes(stringToBytes(a), nbytes))
  end;

# assumes ciphertxt is base64encoded, and key is in hex
function decryptAES128ECBWithKey(ciphertext::String, key::String)
    decrypt = chomp(
        readstring(
            pipeline(`echo -n $ciphertext`,
                     `base64 --decode`,
                     `openssl enc -nopad -d -aes-128-ecb -K $key`,
                     `base64`)))
    return decrypt
end

# takes bytes and returns bytes
function decryptAES128ECBWithKey(cipherbytes::Array{UInt8,1}, keybytes::Array{UInt8,1})
    ciphertext = base64encode(cipherbytes)
    keytext = bytes2hex(keybytes)
    return base64decode(decryptAES128ECBWithKey(ciphertext, keytext))
end

function encryptAES128ECBWithKey(plaintext::String, key::String)
    encrypt = chomp(
        readstring(
            pipeline(`echo -n $plaintext`,
                     `base64 --decode`,
                     `openssl enc -nopad -e -aes-128-ecb -K $key`,
                     `base64`)))
    return encrypt
end

function encryptAES128ECBWithKey(plaintextbytes::Array{UInt8,1}, keybytes::Array{UInt8,1})
    plaintext = base64encode(plaintextbytes)
    keytext = bytes2hex(keybytes)
    return base64decode(encryptAES128ECBWithKey(plaintext, keytext))
end

function encryptCBCByHand(ptbytes::Array{UInt8,1}, blocksize, ivbytes::Array{UInt8,1}, keybytes::Array{UInt8,1})
    cipherbytes = Array{UInt8,1}()
    nblocks = convert(Int64, ceil(length(ptbytes)/blocksize))
    ptbytes = padToNBytes(ptbytes, blocksize*nblocks)
    lastblock = ivbytes
    for ii in 1:nblocks
        bytestoencrypt = ptbytes[((ii-1)*blocksize+1):(ii*blocksize)] $ lastblock
        encryptedbytes = encryptAES128ECBWithKey(bytestoencrypt, keybytes)
        append!(cipherbytes, encryptedbytes)
        lastblock = encryptedbytes
    end
    return cipherbytes
end;

function decryptCBCByHand(ctbytes::Array{UInt8,1}, blocksize, ivbytes::Array{UInt8,1}, keybytes::Array{UInt8,1})
    ptbytes = Array{UInt8,1}()
    nblocks = convert(Int64, length(ctbytes)/blocksize)
    lastblock = ivbytes
    for ii in 1:nblocks
        bytestodecrypt = ctbytes[((ii-1)*blocksize+1):(ii*blocksize)]
        decryptedbytes = decryptAES128ECBWithKey(bytestodecrypt, keybytes) $ lastblock
        append!(ptbytes, decryptedbytes)
        lastblock = bytestodecrypt
    end
    return ptbytes
end;
