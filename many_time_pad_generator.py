from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from Crypto import Random
from binascii import hexlify

from pwn import *


ciphertexts = [
	"This did not seem to encourage the witness at all he kept shifting from",
	"one foot to the other looking uneasily at the Queen and in his",
	"confusion he bit a large piece out of his teacup instead of the bread",
	"Just at this moment Alice felt a very curious sensationshe was",
	"The miserable Hatter dropped his teacup and bread and butter and went",
	"down on one knee Im a poor man Your Majesty he began",
	"You may go said the King and the Hatter hurriedly left the court",
	"The next witness was the Duchesss cook She carried the pepperbox in",
	"her hand and the people near the door began sneezing all at once",
	"The King looked anxiously at the White Rabbit who said in a low voice",
	"Your Majesty must crossexamine this witness",
	"Well if I must I must the King said What are tarts made of",
	"For some minutes the whole court was in confusion and by the time they",
	"had settled down again the cook had disappeared",
	"Never mind said the King call the next witness",
	"Alice watched the White Rabbit as he fumbled over the list Imagine her",
	"surprise when he read out at the top of his shrill little voice the",
	"Here cried Alice She jumped up in such a hurry that she tipped over",
	"the jurybox upsetting all the jurymen on to the heads of the crowd",
	"Oh I beg your pardon she exclaimed in a tone of great dismay",
	"The trial cannot proceed said the King until all the jurymen are",
	"back in their proper placesall he repeated with great emphasis",
	"What do you know about this business the King said to Alice",
	"The King then read from his book Rule fortytwo All persons more",
	"than a mile high to leave the court",
	"Nearly two miles high said the Queen",
	"Well I shant go at any rate said Alice",
	"The King turned pale and shut his notebook hastily Consider your",
	"verdict he said to the jury in a low trembling voice",
	"Theres more evidence to come yet please Your Majesty said the White",
	"Rabbit jumping up in a great hurry This paper has just been picked",
	"up It seems to be a letter written by the prisoner toto somebody He",
	"unfolded the paper as he spoke and added It isnt a letter after all",
	"Please Your Majesty said the Knave I didnt write it and they",
	"cant prove that I did theres no name signed at the end",
	"You must have meant some mischief or else youd have signed your",
	"name like an honest man said the King There was a general clapping of",
	"Read them he added turning to the White Rabbit",
	"There was dead silence in the court whilst the White Rabbit read out the",
	"Thats the most important piece of evidence weve heard yet said the",
	"I dont believe theres an atom of meaning in it ventured Alice",
	"If theres no meaning in it said the King that saves a world of",
	"trouble you know as we neednt try to find any Let the jury consider",
	"No no said the Queen Sentence firstverdict afterwards",
	"Stuff and nonsense said Alice loudly The idea of having the",
	"Hold your tongue said the Queen turning purple",
	"Off with her head the Queen shouted at the top of her voice Nobody",
	"Who cares for you said Alice she had grown to her full size by",
	"this time Youre nothing but a pack of cards",
	"secret: dont_cross_the_streams"
]

stream_length = max(len(c) for c in ciphertexts)

key = b'Very long and confidential key'
stream = Random.new().read(stream_length)

for ciphertext in ciphertexts:
	print(hexlify(xor(ciphertext, stream[:len(ciphertext)])))
