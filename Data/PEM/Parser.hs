{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
-- |
-- Module      : Data.PEM.Parser
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : portable
--
-- Parse PEM content.
--
-- A PEM contains contains from one to many PEM sections.
-- Each section contains an optional key-value pair header
-- and a binary content encoded in base64.
--
module Data.PEM.Parser
    -- ( pemParseBS
    -- , pemParseLBS
    -- )
  where

import Data.Char (isAsciiLower, isAsciiUpper, isDigit)
import Data.Either (partitionEithers, rights)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as BL
import Data.ByteString.Lazy.Char8 qualified as BL8
import Data.List qualified as L

import Data.PEM.Types
import Data.ByteArray.Encoding (Base(Base64), convertFromBase)
import Data.ByteArray qualified as BA

type Line = BL.ByteString

parsePems :: BL.ByteString -> [PEM]
parsePems bl = rights $ go lines
  where
    lines = map unCR $ BL8.lines bl :: [Line]
    go :: [Line] -> [Either [Line] PEM]
    go lines = case parseOne lines of
      Right (nonPemLines, pem, rest) -> Left nonPemLines : Right pem : go rest
      Left err -> []

parseOne :: [Line] -> Either String ([Line], PEM, [Line])
parseOne = \case
  line : rest -> case BL.stripPrefix beginMarker line of
    Just pemFirstLine -> case BL.stripSuffix pemMarker pemFirstLine of
      Just name -> let
        (headers, rest') = parseEncapsulatedHeaders rest
        in do
        (contentLines, rest'') <- getContent name rest'
        bs <- decodeBase64 $ BL.toStrict $ BL.concat contentLines
        let pem = PEM { pemName = BL8.unpack name, pemHeader = headers, pemContent = bs }
        Right ([], pem, rest'')
      Nothing -> Left $ "Can't parse PEM first line suffix: " <> show line
    Nothing -> case parseOne rest of
      Left err -> Left err
      Right (nonPemLines, pem, leftover) -> Right (line : nonPemLines, pem, leftover)
  [] -> Left "No lines to parse a PEM from"
  where
    getContent :: BL.ByteString -> [Line] -> Either String ([Line], [Line])
    getContent name lines_ = go lines_
       where
         go :: [Line] -> Either String ([Line], [Line])
         go = \case
           line : rest -> case BL.stripPrefix endMarker line of
             Just pemLastLine -> case BL.stripSuffix pemMarker pemLastLine of
               Just endName | endName == name -> Right ([], rest)
                            | otherwise -> Left $ "end name doesn't match start name: " <> show (endName, name)
               Nothing -> Left $ "Malformed PEM footer line: " <> show line
             Nothing -> do
               (contentLines, rest') <- go rest
               Right (line : contentLines, rest')
           [] -> Right ([], [])

parseOnePEM :: [Line] -> Either (Maybe String) (PEM, [Line])
parseOnePEM = \case
  [] -> Left Nothing
  l : ls -> case beginMarker `prefixEat` l of
    Nothing -> parseOnePEM ls
    Just n  -> getPemName getPemHeaders n ls

  where getPemName next n ls =
            let (name, rest) = BL.splitAt (BL.length n - 5) n
            in if rest == pemMarker && valid name
            then next (BL8.unpack name) ls
            else Left $ Just $ "invalid PEM delimiter found: " <> show rest

        valid name = BL.null name || BL.last name /= 0x2d

        getPemHeaders name lbs =
            case getPemHeaderLoop lbs of
                Left err           -> Left err
                Right (hdrs, lbs2) -> getPemContent name hdrs initial lbs2
          where getPemHeaderLoop ls = case parseEncapsulatedHeaders ls of
                  (headers, rest) -> if L.null rest
                    then Left $ Just "invalid PEM: no more content in header context"
                    else Right (headers, rest)

        getPemContent name hdrs !contentLines lbs =
            case lbs of
                []     -> Left $ Just "invalid PEM: no end marker found"
                (l:ls) -> case endMarker `prefixEat` l of
                              Nothing ->
                                  let contentLines' = processOneLine contentLines l
                                   in getPemContent name hdrs contentLines' ls
                              Just n  -> getPemName (finalizePem name hdrs contentLines) n ls
        finalizePem name hdrs contentLines nameEnd lbs
            | nameEnd /= name = Left $ Just $ "invalid PEM: end name doesn't match start name: " <> show (nameEnd, name)
            | otherwise       = do
                chunks <- reverseAndPad contentLines
                let pem = PEM { pemName    = name
                              , pemHeader  = hdrs
                              , pemContent = BA.concat chunks }
                return (pem, lbs)

        initial = ([], Nothing)

-- content parse state, holding converted chunks in reverse order and
-- optionally some base64 characters as leftovers from one line to the next
type CState = ([BS.ByteString], Maybe BS.ByteString)

processOneLine :: CState -> Line -> CState
processOneLine (content, leftovers) line =
    go content $ maybe lineChunks (: lineChunks) leftovers
  where
    lineChunks = BL.toChunks (BL8.filter goodChar line)
    goodChar c = isDigit c || isAsciiUpper c || isAsciiLower c
                           || c == '+' || c == '/'
    n = 4

    build x f l xs = let !d = strictDecode x in f (d:l) xs
    {-# INLINE build #-}

    -- adapted from base64-bytestring internal reChunkIn, but also returns
    -- base64 leftovers that could not be used at line end, and should
    -- be used at the begining of the next line, or as part of final padding

    go l []       = (l, Nothing)
    go l (y : ys) =
          case BA.length y `divMod` n of
              (_, 0) -> build y go l ys
              (0, _) -> fixup l y ys
              (d, _) -> let (prefix, suffix) = BA.splitAt (d * n) y
                         in build prefix fixup l suffix ys

    fixup l acc []       = (l, Just acc)
    fixup l acc (z : zs) =
        case BA.splitAt (n - BA.length acc) z of
            (prefix, suffix) ->
                let acc' = acc `BA.append` prefix
                 in if BA.length acc' == n
                        then let zs' = if BA.null suffix
                                           then zs
                                           else suffix : zs
                              in build acc' go l zs'
                       else -- suffix must be null
                           fixup l acc' zs

-- leftovers with 0, 2 or 3 characters are valid end sequences, but
-- only 1 character is a parse error, as this length is not valid for
-- encoded base64 content
reverseAndPad :: CState -> Either (Maybe String) [BS.ByteString]
reverseAndPad (content, leftovers) = fmap reverse (pad leftovers content)
  where
    pad Nothing  l = Right l
    pad (Just b) l =
        case BA.length b `mod` 4 of
            3 -> Right $ strictDecode (b `BA.append` "=")  : l
            2 -> Right $ strictDecode (b `BA.append` "==") : l
            1 -> Left  $ Just "invalid PEM: missing or extra base64 characters"
            _ -> Right $ strictDecode b : l

-- base64 decoding that should never fail, as it is fed only with
-- sequences of valid characters whose length is a multiple of 4
strictDecode :: BS.ByteString -> BS.ByteString
strictDecode = either (\_ -> error "parseOnePEM: invalid chunk detected") id . decodeBase64

{-# INLINE strictDecode #-}

-- | parser to get PEM sections
pemParse :: [Line] -> [Either String PEM]
pemParse l
    | null l    = []
    | otherwise = case parseOnePEM l of
                        Left Nothing         -> []
                        Left (Just err)      -> [Left err]
                        Right (p, remaining) -> Right p : pemParse remaining

-- | parse a PEM content using a strict bytestring
pemParseBS :: BS.ByteString -> Either String [PEM]
pemParseBS b = pemParseLBS $ BL.fromChunks [b]

-- | parse a PEM content using a dynamic bytestring
pemParseLBS :: BL8.ByteString -> Either String [PEM]
pemParseLBS bs = case partitionEithers $ pemParse $ map unCR $ BL8.lines bs of
                    (x:_,_   ) -> Left x
                    ([] ,pems) -> Right pems

-- * Helpers

prefixEat :: BL8.ByteString -> BL8.ByteString -> Maybe BL8.ByteString
prefixEat prefix x =
    let (x1, x2) = BL.splitAt (BL.length prefix) x
     in if x1 == prefix then Just x2 else Nothing

unCR :: BL8.ByteString -> BL8.ByteString
unCR = BL8.dropWhileEnd (== '\r')

beginMarker :: BL8.ByteString
beginMarker = "-----BEGIN "

endMarker :: BL8.ByteString
endMarker = "-----END "

pemMarker :: BL8.ByteString
pemMarker = "-----"

parseEncapsulatedHeaders :: [Line] -> ([Header], [Line])
parseEncapsulatedHeaders ls = let
  (maybeHeader, rest) = parseEncapsulatedHeader ls
  in case maybeHeader of
       Just header -> let (a, b) = parseEncapsulatedHeaders rest in (header : a, b)
       Nothing -> ([], rest)

parseEncapsulatedHeader :: [Line] -> (Maybe Header, [Line])
parseEncapsulatedHeader = \case
  ls@(line : rest) -> let
    (prefix, suffix) = BL8.break (== ':') line
    in if BL.null suffix
    then (Nothing, ls)
    else let
      firstPart = trim $ BL.tail suffix
      (moreParts, rest') = takeSpaced rest
      in (Just (BL8.unpack prefix, BL.toStrict $ BL.concat $ firstPart : moreParts), rest')
  [] -> (Nothing, [])
  where
    trimEnd = BL8.dropWhileEnd (== ' ')
    trim = trimEnd . BL8.dropWhile (== ' ')
    spacedValue line = let (spaces, rest) = BL8.span (== ' ') line
      in if BL.null spaces
      then Nothing
      else Just $ trimEnd rest
    takeSpaced = \case
      lines_@(line : ls) -> case spacedValue line of
        Just value -> let (values, rest) = takeSpaced ls in (value : values, rest)
        Nothing -> ([], lines_)
      [] -> ([], [])

decodeBase64 :: BS.ByteString -> Either String BS.ByteString
decodeBase64 bs = convertFromBase Base64 bs
