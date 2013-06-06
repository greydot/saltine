-- |
-- Module      : Crypto.Saltine.Core.Box
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
-- 
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
-- 
-- Public-key authenticated encryption:
-- "Crypto.Saltine.Core.Box"
-- 
-- The 'box' function encrypts and authenticates a message 'V.Vector'
-- using the sender's secret key, the receiver's public key, and a
-- nonce. The 'boxOpen' function verifies and decrypts a ciphertext
-- 'V.Vector' using the receiver's secret key, the sender's public
-- key, and a nonce. If the ciphertext fails verification, 'boxOpen'
-- returns 'Nothing'.
-- 
-- The "Crypto.Saltine.Core.Box" module is designed to meet the
-- standard notions of privacy and third-party unforgeability for a
-- public-key authenticated-encryption scheme using nonces. For formal
-- definitions see, e.g., Jee Hea An, "Authenticated encryption in the
-- public-key setting: security notions and analyses,"
-- <http://eprint.iacr.org/2001/079>.
-- 
-- Distinct messages between the same @{sender, receiver}@ set are
-- required to have distinct nonces. For example, the
-- lexicographically smaller public key can use nonce 1 for its first
-- message to the other key, nonce 3 for its second message, nonce 5
-- for its third message, etc., while the lexicographically larger
-- public key uses nonce 2 for its first message to the other key,
-- nonce 4 for its second message, nonce 6 for its third message,
-- etc. Nonces are long enough that randomly generated nonces have
-- negligible risk of collision.
-- 
-- There is no harm in having the same nonce for different messages if
-- the @{sender, receiver}@ sets are different. This is true even if
-- the sets overlap. For example, a sender can use the same nonce for
-- two different messages if the messages are sent to two different
-- public keys.
-- 
-- The "Crypto.Saltine.Core.Box" module is not meant to provide
-- non-repudiation. On the contrary: the crypto_box function
-- guarantees repudiability. A receiver can freely modify a boxed
-- message, and therefore cannot convince third parties that this
-- particular message came from the sender. The sender and receiver
-- are nevertheless protected against forgeries by other parties. In
-- the terminology of
-- <http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c>,
-- crypto_box uses "public-key authenticators" rather than "public-key
-- signatures."
-- 
-- Users who want public verifiability (or receiver-assisted public
-- verifiability) should instead use signatures (or
-- signcryption). Signatures are documented in the
-- "Crypto.Saltine.Core.Sign" module.
-- 
-- "Crypto.Saltine.Core.Box" is @curve25519xsalsa20poly1305@, a
-- particular combination of Curve25519, Salsa20, and Poly1305
-- specified in "Cryptography in NaCl"
-- (<http://nacl.cr.yp.to/valid.html>). This function is conjectured
-- to meet the standard notions of privacy and third-party
-- unforgeability.
-- 
-- This is version 2010.08.30 of the box.html web page.
module Crypto.Saltine.Core.Box (
  SecretKey, PublicKey, Keypair, CombinedKey, Nonce,
  newKeypair, beforeNM, newNonce,
  box, boxOpen,
  boxAfterNM, boxOpenAfterNM  
  ) where

import Crypto.Saltine.Class
import Crypto.Saltine.Internal.Util
import Crypto.Saltine.Core.Hash (hash)
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Foreign.C
import Foreign.Ptr
import Data.Word
import qualified Data.Vector.Storable as V
import qualified Data.ByteString.Char8 as S8

import Control.Applicative
import Control.Monad

-- $types

-- | An opaque 'box' cryptographic secret key.
newtype SecretKey = SK (V.Vector Word8) deriving (Eq, Ord)

instance IsEncoding SecretKey where
  decode v = case V.length v == Bytes.boxSK of
    True -> Just (SK v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (SK v) = v
  {-# INLINE encode #-}

instance Show SecretKey where
  show k = "Box.SecretKey {hashesTo = \""
           ++ (take 10 $ S8.unpack $ ashex $ hash k)
           ++ "...\"}"

-- | An opaque 'box' cryptographic public key.
newtype PublicKey = PK (V.Vector Word8) deriving (Eq, Ord)

instance IsEncoding PublicKey where
  decode v = case V.length v == Bytes.boxPK of
    True -> Just (PK v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (PK v) = v
  {-# INLINE encode #-}

instance Show PublicKey where show = ashexShow "Box.PublicKey"

-- | A convenience type for keypairs
type Keypair = (SecretKey, PublicKey)

-- | An opaque 'boxAfterNM' cryptographic combined key.
newtype CombinedKey = CK (V.Vector Word8) deriving (Eq, Ord)

instance IsEncoding CombinedKey where
  decode v = case V.length v == Bytes.boxBeforeNM of
    True -> Just (CK v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (CK v) = v
  {-# INLINE encode #-}

instance Show CombinedKey where
  show k = "Box.CombinedKey {hashesTo = \""
           ++ (take 10 $ S8.unpack $ ashex $ hash k)
           ++ "...\"}"

-- | An opaque 'box' nonce.
newtype Nonce = Nonce (V.Vector Word8) deriving (Eq, Ord)

instance IsEncoding Nonce where
  decode v = case V.length v == Bytes.boxNonce of
    True -> Just (Nonce v)
    False -> Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = v
  {-# INLINE encode #-}

instance IsNonce Nonce where
  zero = Nonce (V.replicate Bytes.boxNonce 0)
  nudge (Nonce n) = Nonce (nudgeVector n)

instance Show Nonce where show = ashexShow "Box.Nonce"

-- | Randomly generates a secret key and a corresponding public key.
newKeypair :: IO Keypair
newKeypair = do
  -- This is a little bizarre and a likely source of errors.
  -- _err ought to always be 0.
  ((_err, sk), pk) <- buildUnsafeCVector' Bytes.boxPK $ \pkbuf ->
    buildUnsafeCVector' Bytes.boxSK $ \skbuf ->
    c_box_keypair pkbuf skbuf
  return (SK sk, PK pk)

-- | Randomly generates a nonce for usage with 'box' and 'boxOpen'.
newNonce :: IO Nonce
newNonce = Nonce <$> randomVector Bytes.boxNonce

-- | Build a 'CombinedKey' for sending from 'SecretKey' to
-- 'PublicKey'. This is a precomputation step which can accelerate
-- later encryption calls.
beforeNM :: SecretKey -> PublicKey -> CombinedKey
beforeNM (SK sk) (PK pk) = CK $ snd $ buildUnsafeCVector Bytes.boxBeforeNM $ \ckbuf ->
  constVectors [pk, sk] $ \[ppk, psk] ->
  c_box_beforenm ckbuf ppk psk

-- | Encrypts a message for sending to the owner of the public
-- key. They must have your public key in order to decrypt the
-- message. It is infeasible for an attacker to decrypt the message so
-- long as the 'Nonce' is not repeated.
box :: IsEncoding a => PublicKey -> SecretKey -> Nonce -> a -> V.Vector Word8
box (PK pk) (SK sk) (Nonce nonce) encmsg =
  unpad' . snd . buildUnsafeCVector len $ \pc ->
    constVectors [pk, sk, pad' msg, nonce] $ \[ppk, psk, pm, pn] ->
    c_box pc pm (fromIntegral len) pn ppk psk
  where len    = V.length msg + Bytes.boxZero
        pad'   = pad Bytes.boxZero
        unpad' = unpad Bytes.boxBoxZero
        msg    = encode encmsg

-- | Decrypts a message sent from the owner of the public key. They
-- must have encrypted it using your secret key. Returns 'Nothing' if
-- the keys and message do not match.
boxOpen :: (IsEncoding a, IsEncoding b)
           => PublicKey -> SecretKey -> Nonce -> a -> Maybe b
boxOpen (PK pk) (SK sk) (Nonce nonce) enccipher =
  let (err, vec) = buildUnsafeCVector len $ \pm ->
        constVectors [pk, sk, pad' cipher, nonce] $ \[ppk, psk, pc, pn] ->
        c_box_open pm pc (fromIntegral len) pn ppk psk
  in decode <=< hush . handleErrno err $ unpad' vec
  where len    = V.length cipher + Bytes.boxBoxZero
        pad'   = pad Bytes.boxBoxZero
        unpad' = unpad Bytes.boxZero
        cipher = encode enccipher

-- | 'box' using a 'CombinedKey' and is thus faster.
boxAfterNM :: IsEncoding a => CombinedKey -> Nonce -> a -> V.Vector Word8
boxAfterNM (CK ck) (Nonce nonce) encmsg =
  unpad' . snd . buildUnsafeCVector len $ \pc ->
    constVectors [ck, pad' msg, nonce] $ \[pck, pm, pn] ->
    c_box_afternm pc pm (fromIntegral len) pn pck
  where len    = V.length msg + Bytes.boxZero
        pad'   = pad Bytes.boxZero
        unpad' = unpad Bytes.boxBoxZero
        msg    = encode encmsg

-- | 'boxOpen' using a 'CombinedKey' and is thus faster.
boxOpenAfterNM :: (IsEncoding a, IsEncoding b)
                  => CombinedKey -> Nonce -> a -> Maybe b
boxOpenAfterNM (CK ck) (Nonce nonce) enccipher =
  let (err, vec) = buildUnsafeCVector len $ \pm ->
        constVectors [ck, pad' cipher, nonce] $ \[pck, pc, pn] ->
        c_box_open_afternm pm pc (fromIntegral len) pn pck
  in decode <=< hush . handleErrno err $ unpad' vec
  where len    = V.length cipher + Bytes.boxBoxZero
        pad'   = pad Bytes.boxBoxZero
        unpad' = unpad Bytes.boxZero
        cipher = encode enccipher


-- | Should always return a 0.
foreign import ccall "crypto_box_keypair"
  c_box_keypair :: Ptr Word8
                   -- ^ Public key
                   -> Ptr Word8
                   -- ^ Secret key
                   -> IO CInt
                   -- ^ Always 0

-- | The secretbox C API uses 0-padded C strings.
foreign import ccall "crypto_box"
  c_box :: Ptr Word8
           -- ^ Cipher 0-padded output buffer
           -> Ptr Word8
           -- ^ Constant 0-padded message input buffer
           -> CULLong
           -- ^ Length of message input buffer (incl. 0s)
           -> Ptr Word8
           -- ^ Constant nonce buffer
           -> Ptr Word8
           -- ^ Constant public key buffer
           -> Ptr Word8
           -- ^ Constant secret key buffer
           -> IO CInt
           -- ^ Always 0

-- | The secretbox C API uses 0-padded C strings.
foreign import ccall "crypto_box_open"
  c_box_open :: Ptr Word8
                -- ^ Message 0-padded output buffer
                -> Ptr Word8
                -- ^ Constant 0-padded ciphertext input buffer
                -> CULLong
                -- ^ Length of message input buffer (incl. 0s)
                -> Ptr Word8
                -- ^ Constant nonce buffer
                -> Ptr Word8
                -- ^ Constant public key buffer
                -> Ptr Word8
                -- ^ Constant secret key buffer
                -> IO CInt
                -- ^ 0 for success, -1 for failure to verify

-- | Single target key precompilation.
foreign import ccall "crypto_box_beforenm"
  c_box_beforenm :: Ptr Word8
                    -- ^ Combined key output buffer
                    -> Ptr Word8
                    -- ^ Constant public key buffer
                    -> Ptr Word8
                    -- ^ Constant secret key buffer
                    -> IO CInt
                    -- ^ Always 0

-- | Precompiled key crypto box. Uses 0-padded C strings.
foreign import ccall "crypto_box_afternm"
  c_box_afternm :: Ptr Word8
                   -- ^ Cipher 0-padded output buffer
                   -> Ptr Word8
                   -- ^ Constant 0-padded message input buffer
                   -> CULLong
                   -- ^ Length of message input buffer (incl. 0s)
                   -> Ptr Word8
                   -- ^ Constant nonce buffer
                   -> Ptr Word8
                   -- ^ Constant combined key buffer
                   -> IO CInt
                   -- ^ Always 0

-- | The secretbox C API uses 0-padded C strings.
foreign import ccall "crypto_box_open_afternm"
  c_box_open_afternm :: Ptr Word8
                        -- ^ Message 0-padded output buffer
                        -> Ptr Word8
                        -- ^ Constant 0-padded ciphertext input buffer
                        -> CULLong
                        -- ^ Length of message input buffer (incl. 0s)
                        -> Ptr Word8
                        -- ^ Constant nonce buffer
                        -> Ptr Word8
                        -- ^ Constant combined key buffer
                        -> IO CInt
                        -- ^ 0 for success, -1 for failure to verify