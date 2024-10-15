import random
import math

class Matrix:
  def __init__(self, matrixList):
    n = len(matrixList)
    m = len(matrixList[0])

    # checking that the column size is equal for each row
    for i in range(len(matrixList)):
      if len(matrixList[i]) != m:
        raise Exception("Invalid Matrix")

    self.matrix = matrixList
    self.n = n
    self.m = m;

  def apply_mod(self, mod):
    for i in range(self.n):
      for j in range(self.m):
        self.matrix[i][j] %= mod

  def apply_constant_multiplication(self, const):
    for i in range(self.n):
      for j in range(self.m):
        self.matrix[i][j] *= const  

  def transpose(self):
    transposeMatrix = [[None]*self.n for _ in range(self.m)]

    for i in range(self.n):
      for j in range(self.m):
        transposeMatrix[j][i] = self.matrix[i][j]

    return Matrix(transposeMatrix)

  def matrix_multiplication(self, otherMatrix):
    if self.m != otherMatrix.n:
      raise Exception("number of column of fist matirx must be equal to number of rows in second matrix")

    resultMatrix = [[0]*otherMatrix.m for _ in range(self.n)]

    for i in range(self.n):
      for j in range(otherMatrix.m):
        for k in range(self.m):
          resultMatrix[i][j] += (self.matrix[i][k] * otherMatrix.matrix[k][j])

    return Matrix(resultMatrix)

  @staticmethod
  def random_matrix(rows, cols, start, stop):
    matrix = []
    for i in range(rows):
      row = []
      for j in range(cols):
        row.append(random.randint(start, stop))

      matrix.append(row)

    return Matrix(matrix)

class SquareMatrix(Matrix):
  def __init__(self, matrixList):
    n = len(matrixList)

    # checking that the column size is equal the row size
    for i in range(len(matrixList)):
      if len(matrixList[i]) != n:
        raise Exception("Invalid Matrix")

    Matrix.__init__(self, matrixList)

  def cofactor(self):
    cofactorMatrix = [[None]*self.n for _ in range(self.n)]

    for i in range(self.n):
      for j in range(self.n):
        minorDeterminant = self.row_col_elimination(i, j).determinant()
        cofactorMatrix[i][j] = ((-1)**(i+j)) * minorDeterminant

    return SquareMatrix(cofactorMatrix)

  # determinant() has a time complexity of O(n!) this is a very very slow function, and later in the report I will explain why it has such time complexity
  def determinant(self):
    if self.n == 1:
      return self.matrix[0][0]

    sign = 1
    res = 0
    for j in range(self.n):
      subMatrix = self.row_col_elimination(0, j)
      res += (sign * self.matrix[0][j] * subMatrix.determinant())
      sign *= -1

    return res

  def row_col_elimination(self, row, col):
    subMatrix = [[None]*(self.n-1) for _ in range(self.n-1)]

    for i in range(self.n):
      for j in range(self.n):
        if i == row or j == col:
          continue

        r = i if i < row else i - 1
        c = j if j < col else j - 1
        subMatrix[r][c] = self.matrix[i][j]

    return SquareMatrix(subMatrix)

def generate_key_matrix(n, start, stop):
  while True:
    matrix = Matrix.random_matrix(n, n, start, stop)
    matrix = SquareMatrix(matrix.matrix)
    if matrix.determinant() != 0 and math.gcd(matrix.determinant(), 26) == 1:
      return matrix

def key_matrix_inverse(key_matrix):
  inverse = key_matrix.cofactor().transpose()
  inverse.apply_constant_multiplication(pow(key_matrix.determinant(), -1, 26))
  inverse.apply_mod(26)

  return inverse

def split_string(str, n):
  blocks = []
  substr = ""
  substr_indices = []

  for i, char in enumerate(str):
    if len(substr) == n:
      blocks.append((substr, substr_indices))
      substr = ""
      substr_indices = []

    if 'A' <= char <= 'Z':
      substr += char
      substr_indices.append(i)

  if (len(substr) != 0):
    substr += 'Z' * (n - len(substr))
    blocks.append((substr, substr_indices))

  return blocks

def encrypt_block(plain_text, key_matrix):
  n = len(plain_text)
  if (key_matrix.n != n):
    raise Exception("Key Matrix should have dimensions equal to the plain text")

  plain_text_vector = [[0] for _ in range(n)]
  for i in range(n):
    character = plain_text[i]
    plain_text_vector[i][0] = ord(character) - ord('A')

  encrypted_text_vector = key_matrix.matrix_multiplication(Matrix(plain_text_vector))
  encrypted_text_vector.apply_mod(26)
  encrypted_text_vector = encrypted_text_vector.matrix

  encrypted_text = ""
  for i in range(len(encrypted_text_vector)):
    encrypted_text += chr(encrypted_text_vector[i][0] + ord('A'))

  return encrypted_text

def encrypt(plain_text, key_matrix):
  n = key_matrix.n
  cipher_text = []
  for chr in plain_text:
    cipher_text.append(chr)

  blocks = split_string(plain_text, n)
  for block in blocks:
    block_encryption = encrypt_block(block[0], key_matrix)
    for i in range(n):
      if i < len(block[1]):
        cipher_text[block[1][i]] = block_encryption[i]
      else:
        cipher_text.append(block_encryption[i]) # this is to include the padding

  return ''.join(cipher_text)

def decrypt_block(cipher_text, keyMatrixInverse):
  n = len(cipher_text)
  if (keyMatrixInverse.n != n):
    raise Exception("Key Matrix should have dimensions equal to the cipher text")

  cipher_text_vector = [[0] for _ in range(n)]
  for i in range(n):
    character = cipher_text[i]
    cipher_text_vector[i][0] = ord(character) - ord('A')

  cipher_text_vector = keyMatrixInverse.matrix_multiplication(Matrix(cipher_text_vector))
  cipher_text_vector.apply_mod(26)
  cipher_text_vector = cipher_text_vector.matrix

  decrypted_text = ""
  for i in range(len(cipher_text_vector)):
    decrypted_text += chr(cipher_text_vector[i][0] + ord('A'))

  return decrypted_text

def decrypt(cipher_text, key_matrix):
  n = key_matrix.n
  keyMatrixInverse = key_matrix_inverse(key_matrix)

  plain_text = []
  for chr in cipher_text:
    plain_text.append(chr)

  blocks = split_string(cipher_text, n)
  for block in blocks:
    block_decryption = decrypt_block(block[0], keyMatrixInverse)
    for i in range(n):
      plain_text[block[1][i]] = block_decryption[i]

  return ''.join(plain_text)

if __name__ == "__main__":
  key_matrix = generate_key_matrix(3, 0, 25)

  plain_text = input("Please enter plain text: ")
  cipher_text = encrypt(plain_text, key_matrix)
  print("Cipher Text: ", cipher_text)

  decrypted_text = decrypt(cipher_text, key_matrix)
  padding = len(decrypted_text) - len(plain_text)
  print("Plain with padding: ", decrypted_text)

  if padding != 0:
    print("Plain: ", decrypted_text[:-padding])
  else:
    print("Plain: ", decrypted_text)