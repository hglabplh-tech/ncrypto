;; Copyright 2023-2025 Harald Glab-Plhak
;;
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation either version 3 of the License or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not see <http://www.gnu.org/licenses/>.

#lang racket/base
(require (only-in srfi/1 iota)
         (only-in srfi/60 rotate-bit-field)
         binaryio/integer
         rnrs/arithmetic/bitwise-6
         "../utils/basic-sig-utils.rkt"
         "../utils/endianess.rkt"        
         )

(provide (all-defined-out))
