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
         racket/vector
         "../utils/basic-sig-utils.rkt"
         "../utils/endianess.rkt"
         "aes-list-tables.rkt"
         )

(provide (all-defined-out))


(define (mod-vect-ret-new vect pos val)
  (let ([ret-vect vect])
    (vector-set! ret-vect pos val)
    ret-vect))

(define (round-calc128 round-key-vect rk-add)
  (let round-128 ([rkey-vect round-key-vect]
                  [index 0]
                  [rk-offset 0])
    (cond [(< index 10)
           (let* ([temp (vector-ref rkey-vect (+ rk-offset 3))]
                  [rkey-vect-int (vector-append rkey-vect
                                                (make-vector 1
                                                             ( bitwise-xor
                                                               (vector-ref rkey-vect (rk-offset + 0))
                                                               (bitwise-and (list-ref list-te4-encr
                                                                                      (bitwise-and (>> temp 16) #xff))#xff000000)
                                                               (bitwise-and (list-ref list-te4-encr
                                                                                      (bitwise-and (>> temp 8) #xff)) #x00ff0000)
                                                               (bitwise-and (list-ref list-te4-encr
                                                                                      (bitwise-and (>> temp 0) #xff)) #x0000ff00)
                                                               (bitwise-and (list-ref list-te4-encr
                                                                                      (bitwise-and (>> temp 24) #xff))#x000000ff)
                                                               (list-ref rcon index))))]
                  [rkey-vect-int (vector-append (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 1))
                                                                            (vector-ref rkey-vect-int (rk-offset + 4))))
                                                (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 2))
                                                                            (vector-ref rkey-vect-int (rk-offset + 5))))
                                                (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 3))
                                                                            (vector-ref rkey-vect-int (rk-offset + 6))))
                                                )])
             (round-128 rkey-vect-int (add1 index) (+ rk-offset rk-add)))]
          [rkey-vect])))

(define (round-calc192 round-key-vect rk-add)
  (let round-192 ([rkey-vect round-key-vect]
                  [index 0]
                  [rk-offset 0])
     
    (let* ([temp (vector-ref rkey-vect (+ rk-offset 5))]
           [rkey-vect-int (vector-append rkey-vect
                                         (make-vector 1
                                                      ( bitwise-xor
                                                        (vector-ref rkey-vect (rk-offset + 0))
                                                        (bitwise-and (list-ref list-te4-encr
                                                                               (bitwise-and (>> temp 16) #xff))#xff000000)
                                                        (bitwise-and (list-ref list-te4-encr
                                                                               (bitwise-and (>> temp 8) #xff)) #x00ff0000)
                                                        (bitwise-and (list-ref list-te4-encr
                                                                               (bitwise-and (>> temp 0) #xff)) #x0000ff00)
                                                        (bitwise-and (list-ref list-te4-encr
                                                                               (bitwise-and (>> temp 24) #xff))#x000000ff)
                                                        (list-ref rcon index))))]
           [rkey-vect-int (vector-append (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 1))
                                                                     (vector-ref rkey-vect-int (rk-offset + 6))))
                                         (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 2))
                                                                     (vector-ref rkey-vect-int (rk-offset + 7))))
                                         (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 3))
                                                                     (vector-ref rkey-vect-int (rk-offset + 8))))
                                         )])
      (cond [(eq? index 7)
             rkey-vect]
            [(let* ([rkey-vect-int (vector-append (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 4))
                                                                              (vector-ref rkey-vect-int (rk-offset + 9))))
                                                  (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 5))
                                                                              (vector-ref rkey-vect-int (rk-offset + 10)))))])
               (round-192 rkey-vect-int (add1 index) (+ rk-offset rk-add)))]
               
            ))))

(define (round-calc256 round-key-vect rk-add)
  (let round-192 ([rkey-vect round-key-vect]
                  [index 0]
                  [rk-offset 0])
     
    (let* ([temp (vector-ref rkey-vect (+ rk-offset 7))]
           [rkey-vect-int (vector-append rkey-vect
                                         (make-vector 1
                                                      ( bitwise-xor
                                                        (vector-ref rkey-vect (rk-offset + 0))
                                                        (bitwise-and (list-ref list-te4-encr
                                                                               (bitwise-and (>> temp 16) #xff))#xff000000)
                                                        (bitwise-and (list-ref list-te4-encr
                                                                               (bitwise-and (>> temp 8) #xff)) #x00ff0000)
                                                        (bitwise-and (list-ref list-te4-encr
                                                                               (bitwise-and (>> temp 0) #xff)) #x0000ff00)
                                                        (bitwise-and (list-ref list-te4-encr
                                                                               (bitwise-and (>> temp 24) #xff))#x000000ff)
                                                        (list-ref rcon index))))]
           [rkey-vect-int (vector-append (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 1))
                                                                     (vector-ref rkey-vect-int (rk-offset + 8))))
                                         (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 2))
                                                                     (vector-ref rkey-vect-int (rk-offset + 9))))
                                         (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 3))
                                                                     (vector-ref rkey-vect-int (rk-offset + 10))))
                                         )])
      (cond [(eq? index 6)
             rkey-vect]
            [(let* ([rkey-vect-int (vector-append
                                    (make-vector 1
                                                 ( bitwise-xor
                                                   (vector-ref rkey-vect (rk-offset + 4))
                                                   (bitwise-and (list-ref list-te4-encr
                                                                          (bitwise-and (>> temp 24) #xff))#xff000000)
                                                   (bitwise-and (list-ref list-te4-encr
                                                                          (bitwise-and (>> temp 16) #xff))#x00ff0000)
                                                   (bitwise-and (list-ref list-te4-encr
                                                                          (bitwise-and (>> temp 8) #xff)) #x0000ff00)
                                                   (bitwise-and (list-ref list-te4-encr
                                                                          (bitwise-and (>> temp 0) #xff)) #x000000ff)
                                                   (list-ref rcon index)))
                                    (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 5))
                                                                (vector-ref rkey-vect-int (rk-offset + 12))))
                                    (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 6))
                                                                (vector-ref rkey-vect-int (rk-offset + 13))))
                                    (make-vector 1 (bitwise-xor (vector-ref rkey-vect-int (rk-offset + 7))
                                                                (vector-ref rkey-vect-int (rk-offset + 14)))))])
               (round-192 rkey-vect-int (add1 index) (+ rk-offset rk-add)))]
               
            ))))

            
            
                    

         
(define (setup-encode cipher-key key-bits)
  (let* ([round-key null]
         [round-key (append round-key (list (bytes->32-big (subbytes cipher-key 0 4))))]
         [round-key (append round-key (list (bytes->32-big (subbytes cipher-key 4 4))))]
         [round-key (append round-key (list (bytes->32-big (subbytes cipher-key 8 4))))]
         [round-key (append round-key (list (bytes->32-big (subbytes cipher-key 12 4))))]
         [round-key-vect (list->vector round-key)])
    (cond [(eq? key-bits 128)
           (values 10 (round-calc128 round-key-vect 4))])
    (let* ([round-key-vect (vector-append
                            round-key-vect
                            (make-vector 1
                                         (bytes->32-big (subbytes cipher-key 16 4))))]
           [round-key-vect (vector-append
                            round-key-vect
                            (make-vector 1
                                         (bytes->32-big (subbytes cipher-key 20 4))))]
           (cond [(eq? key-bits 192)
                  (values 12 (round-calc192 round-key-vect 6))]))
      (let* ([round-key-vect (vector-append
                              round-key-vect
                              (make-vector 1
                                           (bytes->32-big (subbytes cipher-key 24 4))))]
             [round-key-vect (vector-append
                              round-key-vect
                              (make-vector 1
                                           (bytes->32-big (subbytes cipher-key 28 4))))])
        (cond [(eq? key-bits 256)
               (values 14 (round-calc256 round-key-vect 8))]))
           
      round-key))) ;; here follows the calculation !!!
