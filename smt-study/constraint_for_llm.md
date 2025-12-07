# Constraint Format for LLM

(>= x k)                     -> x must be ≥ k
(<= x k)                     -> x must be ≤ k
(= x k)                      -> x must be equal to k
(not (= x k))                -> x must not equal k
(> x k)                      -> x must be > k
(< x k)                      -> x must be < k
(or (= x a) (= x b))         -> x must be either a or b
(and C1 C2 C3)               -> expand into multiple constraints
(= (select arr idx) k)       -> arr[idx] must equal k
(not (= (select arr idx) k)) -> arr[idx] must not equal k
(contains s "abc")           -> string s must contain substring "abc"
(not (contains s "abc"))     -> string s must not contain substring "abc"
(startswith s "abc")         -> string s must start with "abc"
(endswith s "abc")           -> string s must end with "abc"
(= (length s) K)             -> length of s must be K
