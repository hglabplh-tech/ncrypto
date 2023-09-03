; Copyright 2023-2025 Harald Glab-Plhak
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

;; Used Code of C. K. Young as base
;;https://stackoverflow.com/questions/24093199/a-pure-scheme-implementation-r5rs-of-sha256
;; changed code to our needs based on NIST papers for sha

#lang racket/base

(require "basic-sig-utils.rkt")
  
(provide (all-defined-out))

(define (do-padding the-bytes block-len type)
  (case type
    ['pkcs7
     (do-pkcs7-padding the-bytes)]))

(define (do-pkcs7-padding the-bytes block-len)
  (let* ([length (bytes-length the-bytes)]
         [pad-length  (- block-len length)]
         [pad-block (cond [(> pad-length 0)
                            (make-bytes pad-length (u8+ pad-length))]
                           [else the-bytes])])
    (cond [(equal? the-bytes pad-block) the-bytes]
          [else (bytes-append the-bytes pad-block)])))
          
