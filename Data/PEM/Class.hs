module Data.PEM.Class where

import Data.PEM.Types

class ToPEM a where
  toPEM :: a -> PEM
