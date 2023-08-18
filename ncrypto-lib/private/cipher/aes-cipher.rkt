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
         "cipher-ctx.rkt"
         )

(provide (all-defined-out))




;; look for explanations for the different functions in the specification to use them as comments
(define (mod-vect-ret-new vect pos val len)
  (let ([ret-vect vect])
    (vector-set! ret-vect pos val)
    ret-vect))

(define (swap-vect-mem vect pos-a pos-b len)
  (let* ([temp (vector-ref vect pos-a)]
         [rkey-vect (mod-vect-ret-new vect pos-a (vector-ref vect pos-b))]
         [rkey-vect (mod-vect-ret-new vect pos-b temp)])
    vect))

(define(make-regs-calc s0 s1 s2 s3 t0 t1 t2 t3)
  (hasheq 
   'S0 s0 'S1 s1 'S2 s2 'S3 s3 'T0 t0 'T1 t1 'T2 t2 'T3 t3))

(define regs-to-s (list
                   (list 'S0 'T0)
                   (list 'S1 'T1)
                   (list 'S2 'T2)
                   (list 'S3 'T3)
                   ))

(define regs-to-t (list
                   (list 'T0 'S0)
                   (list 'T1 'S1)
                   (list 'T2 'S2)
                   (list 'T3 'S3)
                   ))

          

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

            
            
                    

         
(define (aes-setup-encode cipher-key key-bits)
  (let* ([round-key null]
         [round-key (append round-key (list (u32+ (bytes->32-big (subbytes cipher-key 0 4)))))]
         [round-key (append round-key (list (u32+ (bytes->32-big (subbytes cipher-key 4 4)))))]
         [round-key (append round-key (list (u32+ (bytes->32-big (subbytes cipher-key 8 4)))))]
         [round-key (append round-key (list (bytes->32-big (subbytes cipher-key 12 4))))]
         [round-key-vect (list->vector round-key)])
    (cond [(eq? key-bits 128)
           (values 10 (round-calc128 round-key-vect 4))])
    (let* ([round-key-vect (vector-append
                            round-key-vect
                            (make-vector 1
                                         (u32+ (bytes->32-big (subbytes cipher-key 16 4)))))]
           [round-key-vect (vector-append
                            round-key-vect
                            (make-vector 1
                                         (u32+ (bytes->32-big (subbytes cipher-key 20 4)))))]
           (cond [(eq? key-bits 192)
                  (values 12 (round-calc192 round-key-vect 6))]))
      (let* ([round-key-vect (vector-append
                              round-key-vect
                              (make-vector 1
                                           (u32+ (bytes->32-big (subbytes cipher-key 24 4)))))]
             [round-key-vect (vector-append
                              round-key-vect
                              (make-vector 1
                                           (u32+ (bytes->32-big (subbytes cipher-key 28 4)))))])
        (cond [(eq? key-bits 256)
               (values 14 (round-calc256 round-key-vect 8))]))))
           
  ) 


(define (aes-setup-decode cipher-key key-bits)
  (let-values ([(nr round-key-vect) (aes-setup-encode cipher-key key-bits)])
    (let ([rkey-vect-2 
           (let loop-through ([i 4]
                              [j (- (* 4 nr) 4)]          
                              [rkey-vect round-key-vect])
             (cond [(< i j)             
                    ;;temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
                    (let* ([temp (vector-ref rkey-vect i)]
                           [rkey-vect (swap-vect-mem rkey-vect i j)]
                           [rkey-vect (swap-vect-mem rkey-vect (+ i 1) (+ j 1))]
                           [rkey-vect (swap-vect-mem rkey-vect (+ i 2) (+ j 2))]
                           [rkey-vect (swap-vect-mem rkey-vect (+ i 3) (+ j 3))])
                      (loop-through (+ i 4) (- j 4) rkey-vect))]
                   [rkey-vect]))])
      (let loop-through-fin ([rkey-vect-fin rkey-vect-2]
                             [i 1]
                             [rk-offset 4])
        (cond [(< i nr)
               (let* ([temp (vector-ref rkey-vect-fin (+ rk-offset 0))]
                      [rkey-vect-fin (mod-vect-ret-new rkey-vect-fin  (+ rk-offset 0) (list-ref (bitwise-xor
                                                                                                 ;; maybe change all occur. of bit shift 24 see original source
                                                                                                 (list-ref list-td0-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp 24) #xff) #xff))))
                                                                                                 (list-ref list-td1-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp 16) #xff) #xff))))
                                                                                                 (list-ref list-td2-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp  8) #xff) #xff))))
                                                                                                 (list-ref list-td3-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp 0) #xff) #xff)))))))]
                      [temp (vector-ref rkey-vect-fin (+ rk-offset 1))]
                      [rkey-vect-fin (mod-vect-ret-new rkey-vect-fin  (+ rk-offset 1) (list-ref (bitwise-xor
                                                                                                 (list-ref list-td0-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp 24) #xff) #xff))))
                                                                                                 (list-ref list-td1-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp 16) #xff) #xff))))
                                                                                                 (list-ref list-td2-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp  8) #xff) #xff))))
                                                                                                 (list-ref list-td3-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp 0) #xff) #xff)))))))]
                      [temp (vector-ref rkey-vect-fin (+ rk-offset 2))]
                      [rkey-vect-fin (mod-vect-ret-new rkey-vect-fin  (+ rk-offset 2) (list-ref (bitwise-xor
                                                                                                 (list-ref list-td0-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp 24) #xff) #xff))))
                                                                                                 (list-ref list-td1-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp 16) #xff) #xff))))
                                                                                                 (list-ref list-td2-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp  8) #xff) #xff))))
                                                                                                 (list-ref list-td3-decr
                                                                                                           (bitwise-and (list-ref list-te4-encr
                                                                                                                                  (bitwise-and
                                                                                                                                   (bitwise-and (>> temp 0) #xff) #xff)))))))]
                      [temp (vector-ref rkey-vect-fin (+ rk-offset (+ rk-offset 0)))]
                      [rkey-vect-fin (mod-vect-ret-new rkey-vect-fin 3 (list-ref (bitwise-xor
                                                                                  (list-ref list-td0-decr
                                                                                            (bitwise-and (list-ref list-te4-encr
                                                                                                                   (bitwise-and
                                                                                                                    (bitwise-and (>> temp 24) #xff) #xff))))
                                                                                  (list-ref list-td1-decr
                                                                                            (bitwise-and (list-ref list-te4-encr
                                                                                                                   (bitwise-and
                                                                                                                    (bitwise-and (>> temp 16) #xff) #xff))))
                                                                                  (list-ref list-td2-decr
                                                                                            (bitwise-and (list-ref list-te4-encr
                                                                                                                   (bitwise-and
                                                                                                                    (bitwise-and (>> temp  8) #xff) #xff))))
                                                                                  (list-ref list-td3-decr
                                                                                            (bitwise-and (list-ref list-te4-encr
                                                                                                                   (bitwise-and
                                                                                                                    (bitwise-and (>> temp 0) #xff) #xff)))))))])
                 (loop-through-fin rkey-vect-fin (add1 i) (+ rk-offset 4))
                 )]
              [(values nr rkey-vect-fin)])))))

;;/* round 1: */
    ;;t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
    ;;t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
    ;;t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
    ;;t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];

(define (really-calculate-round round-key-offset round-key regs)
  (let* ([rk-offset round-key-offset]
         [result (set-reg regs 'T0 (bitwise-xor
                          (list-ref list-te0-encr (>> (u32+ (regs-ref regs 'S0) 24)))
                          (list-ref list-te1-encr (bitwise-and (>> (u32+ (regs-ref regs 'S1) 16)) (u32+ #xff)))
                          (list-ref list-te2-encr (bitwise-and (>> (u32+ (regs-ref regs 'S2) 8)) (u32+ #xff)))
                          (list-ref list-te3-encr (bitwise-and (u32+ (regs-ref regs 'S2)) (u32+ #xff)))
                          (u32+ (vector-ref round-key rk-offset))))]
         [rk-offset (add1 rk-offset)]
         [result (set-reg result 'T1 (bitwise-xor
                          (list-ref list-te0-encr (>> (u32+ (regs-ref regs 'S1) 24)))
                          (list-ref list-te1-encr (bitwise-and (>> (u32+ (regs-ref regs 'S2) 16)) (u32+ #xff)))
                          (list-ref list-te2-encr (bitwise-and (>> (u32+ (regs-ref regs 'S3) 8)) (u32+ #xff)))
                          (list-ref list-te3-encr (bitwise-and (u32+ (regs-ref regs 'S0)) (u32+ #xff)))
                          (u32+ (vector-ref round-key rk-offset))))]
         [rk-offset (add1 rk-offset)]
          [result (set-reg 'T2 (bitwise-xor
                          (list-ref list-te0-encr (>> (u32+ (regs-ref regs 'S2) 24)))
                          (list-ref list-te1-encr (bitwise-and (>> (u32+ (regs-ref regs 'S3) 16)) (u32+ #xff)))
                          (list-ref list-te2-encr (bitwise-and (>> (u32+ (regs-ref regs 'S0) 8)) (u32+ #xff)))
                          (list-ref list-te3-encr (bitwise-and (u32+ (regs-ref regs 'S1)) (u32+ #xff)))
                          (u32+ (vector-ref round-key rk-offset))))]
          [rk-offset (add1 rk-offset)]
          [result (set-reg 'T1 (bitwise-xor
                          (list-ref list-te0-encr (>> (u32+ (regs-ref regs 'S3) 24)))
                          (list-ref list-te1-encr (bitwise-and (>> (u32+ (regs-ref regs 'S0) 16)) (u32+ #xff)))
                          (list-ref list-te2-encr (bitwise-and (>> (u32+ (regs-ref regs 'S1) 8)) (u32+ #xff)))
                          (list-ref list-te3-encr (bitwise-and (u32+ (regs-ref regs 'S2)) (u32+ #xff)))
                          (u32+ (vector-ref round-key rk-offset))))]
          [rk-offset (add1 rk-offset)])
    (values rk-offset result)))
         
                          
(define (aes-final-load-encr-bytes regs round-key nr)
  (let* ([rk-offset (u32+ (<< nr 2))]
        [out (32->bytes-big (u32+ (bitwise-xor
                             (u32+ (bitwise-and (list-ref list-te4-encr (>> (u32+ (regs-ref regs 'T0) 24)))                    #xff000000))
                             (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (>> (u32+ (regs-ref regs 'T1) 16)) #xff)) #x00ff0000))
                             (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (>> (u32+ (regs-ref regs 'T2) 8)) #xff))  #x0000ff00))
                              (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (u32+ (regs-ref regs 'T3)) #xff))        #x000000ff))
                              (u32+ (vector-ref round-key (+ rk-offset 0)))
                             )))]
         [out (bytes-append out (32->bytes-big (u32+ (bitwise-xor
                             (u32+ (bitwise-and (list-ref list-te4-encr (>> (u32+ (regs-ref regs 'T1) 24)))                    #xff000000))
                             (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (>> (u32+ (regs-ref regs 'T2) 16)) #xff)) #x00ff0000))
                             (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (>> (u32+ (regs-ref regs 'T3) 8)) #xff))  #x0000ff00))
                              (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (u32+ (regs-ref regs 'T0)) #xff)) #x000000ff))
                              (u32+ (vector-ref round-key (+ rk-offset 1)))
                             ))))]
         [out (bytes-append out (32->bytes-big (u32+ (bitwise-xor
                             (u32+ (bitwise-and (list-ref list-te4-encr (>> (u32+ (regs-ref regs 'T2) 24)))                    #xff000000))
                             (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (>> (u32+ (regs-ref regs 'T3) 16)) #xff)) #x00ff0000))
                             (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (>> (u32+ (regs-ref regs 'T0) 8)) #xff))  #x0000ff00))
                              (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (u32+ (regs-ref regs 'T1)) #xff)) #x000000ff))
                              (u32+ (vector-ref round-key (+ rk-offset 2)))
                             ))))]
          [out (bytes-append out (32->bytes-big (u32+ (bitwise-xor
                             (u32+ (bitwise-and (list-ref list-te4-encr (>> (u32+ (regs-ref regs 'T3) 24)))                    #xff000000))
                             (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (>> (u32+ (regs-ref regs 'T0) 16)) #xff)) #x00ff0000))
                             (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (>> (u32+ (regs-ref regs 'T1) 8)) #xff))  #x0000ff00))
                              (u32+ (bitwise-and (list-ref list-te4-encr (bitwise-and (u32+ (regs-ref regs 'T2)) #xff)) #x000000ff))
                              (u32+ (vector-ref round-key (+ rk-offset 3)))
                             ))))])
      out))

(define (aes-encrypt round-key nr in-bytes)
  (let ([regs-calc (make-regs-calc 0 0 0 0 0 0 0 0)])
    (let* ([rounds (cond [(eq? nr 10) 9]
                  [(eq? nr 12) 11]
                  [(eq? nr 14) 13])] ;;TODO: really calc rounds
           [regs (set-reg 'S0 (bitwise-xor (u32+ (bytes->32-big (subbytes in-bytes 0  4))) (u32+ (vector-ref round-key 0))))]
           [regs (set-reg 'S1 (bitwise-xor (u32+ (bytes->32-big (subbytes in-bytes 4  4))) (u32+ (vector-ref round-key 1))))]
           [regs (set-reg 'S2 (bitwise-xor (u32+ (bytes->32-big (subbytes in-bytes 8  4))) (u32+ (vector-ref round-key 2))))]
           [regs (set-reg 'S2 (bitwise-xor (u32+ (bytes->32-big (subbytes in-bytes 12 4))) (u32+ (vector-ref round-key 3))))])
      (let calc-round ([regs-calc-int regs]
                       [rk-offset-int 4]
                       [round 1])
        (let-values ([(rk-offset regs-int)
                      (really-calculate-round rk-offset-int round-key regs-calc-int)])
          (cond [(<= round rounds)
                 (let ([regs-to-call (cond [(< round rounds)
                                            (assign-regs regs-int regs-to-s)]
                                           [regs-int])])
                 (calc-round regs-int (add1 rk-offset) (add1 round))) ] ;; think about conditions if they are ok
                [(aes-final-load-encr-bytes regs-int round-key nr )]);; correct this and format this can be extracted
                   )))))
                   ;; really do finalize computation here
          
          

(define (aes-decrypt round-key nr in-bytes)
  #f)
  
                             
          
          
            
        
;;here the interface functions take place
(define (aes-block-init cipher key-len)
  (let ([nr (cond [(eq? key-len 16) 10]
                  [(eq? key-len 24) 12]
                  [(eq? key-len 32) 14])])
    (let-values ([(nr-encode encr-key) (aes-setup-encode cipher (* 8 key-len))]
                 [(nr-decode decr-key) (aes-setup-decode cipher (* 8 key-len))])
      (cipher-state-aes encr-key decr-key nr)))) 

(define (aes-block-encrypt block-state in)
  (let ([result (aes-encrypt (cipher-state-aes-encr-key block-state)
                             (cipher-state-aes-rounds block-state) in)])
    result))

(define (aes-block-decrypt block-state in)
  (let ([result (aes-decrypt (cipher-state-aes-decr-key block-state)
                             (cipher-state-aes-rounds block-state) in)])
    result))


          
    
