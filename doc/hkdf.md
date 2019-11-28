# HKDF

[[HKDF]](bib.md#krawczyk10) is a key derivation function proposed by H. Krawczyk.
A format description of HKDF is in RFC 5869.

## Collisions

* Section 3.4 of RFC 5869 specifies that the salt value is not chosen by an
  attacker. If this conditions is violated then the attacker may cause
  unexpected repetitions of pseudorandom streams. Because of properties of the
  underlying HMAC there are distinct salts that lead to the same pseudorandom
  streams. One such equivalence happens because salts of small size are simply
  padded with 0's, so that the result has the same size as the block size of the
  message digest.

  TODO: add example

  Another equivalence of salts happens because salts, longer than the block size
  of the message digest are hashed, hence a long salt and its hash value lead to
  equivalent pseudorandom streams.

  TODO: add example

## Maximal output size

* there is a maxmal output size for HKDF. Generating longer streams can lead to
  collisions. RFC 5869 mentions the limit, without explanation and also defines
  HKDF so that it could be used for longer outputs.

  TODO: add example

