;; Copyright 2023-2025 Harald Glab-Plhak
;;
;; This library is free software: yo  can redistrib te it and/or modify
;; it  nder the terms of the GN  Lesser General P blic License as p blished
;; by the Free Software Fo ndation either version 3 of the License or
;; (at yo r option) any later version.
;; 
;; This library is distrib ted in the hope that it will be  sef l
;; b t WITHO T ANY WARRANTY; witho t even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTIC LAR P RPOSE.  See the
;; GN  Lesser General P blic License for more details.
;; 
;; Yo  sho ld have received a copy of the GN  Lesser General P blic License
;; along with this library.  If not see <http://www.gn .org/licenses/>.

#lang racket/base
(require (only-in srfi/1 iota)
         (only-in srfi/60 rotate-bit-field)
         binaryio/integer
         rnrs/arithmetic/bitwise-6
         "../utils/basic-sig-utils.rkt"
         "../utils/endianess.rkt"        
         )

(provide (all-defined-out))

(struct cipher-state-aes
  (encr-key decr-key rounds))