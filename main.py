import unidecode
import numpy as np

content_gutenbergEBook = 0


def format_text(text):
    """
    Formats a text so that it contains only uppercase letters without spaces
    :param text: texto to format
    :return: formatted text
    """
    if len(text) == 0:
        raise Exception("Empty text")

    # Remove accent from text
    text = unidecode.unidecode(text)

    formated_text = ""
    for c in text:
        c = check_input(c)
        if c != "":
            formated_text += c.upper()

    return formated_text


def count_alpha_char_occurence(text):
    freq_vector = [0] * 26

    formated_text = format_text(text)

    for c in formated_text:
        freq_vector[ord(c) - 65] += 1

    return freq_vector


def shift_char_by_index(index, key):
    """
    Shift a char with an offset value
    :param index: index of the char to shift
    :param key: value of the offset
    :return: the shifted char
    """
    # shifting
    shifted_index = (index + key) % 26

    # return to the shifted char
    shifted_unicode = shifted_index + ord("A")

    # return and convert the shifted char
    return chr(shifted_unicode)


def check_input(char):
    """
    Check if it is an uppercase alpha char. If it is not in uppercase, switch the char in uppercase.
    :param char: char to check
    :return: the uppercase alpha char or empty string if it not an alpha char
    """
    if (ord(char) >= 97) and (ord(char) <= 122):
        # Up the char
        char = char.upper()

    # test if it is the char is between [A-Z]
    if (ord(char) >= 65) and (ord(char) <= 90):
        return char

    return ""


def caesar_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the shift which is a number

    Returns
    -------
    the ciphertext of <text> encrypted with Caesar under key <key>
    """
    # TODO

    text = format_text(text)
    if not key.isdigit():
        raise Exception("Caesar must be only digit")

    ciphertext = ""

    for c in text:
        # ord() give ASCII position of a char
        c_index = ord(c) - ord("A")  # ord("A") = 65

        ciphertext += shift_char_by_index(c_index, key)

    return ciphertext


def caesar_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the shift which is a number

    Returns
    -------
    the plaintext of <text> decrypted with Caesar under key <key>
    """
    # TODO
    return caesar_encrypt(text, ((-1) * key) % 26)  # %26 To be safe


def freq_analysis(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    list
        the frequencies of every letter (a-z) in the text.
    """
    # TODO
    freq_vector = count_alpha_char_occurence(text)

    text_len = np.sum(freq_vector, dtype=np.float64)

    for i in range(26):
        freq_vector[i] /= text_len

    return freq_vector


def caesar_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break

    Returns
    -------
    a number corresponding to the caesar key
    """
    # TODO

    text = format_text(text)

    E = freq_analysis(content_gutenbergEBook)

    caesar_keys = [0] * 26
    caesar_key = 0

    # Get ciphertext frequencies
    O = freq_analysis(caesar_decrypt(text, 0))

    for i in range(26):
        for j in range(26):
            # O[(i + j) % 26]  Prefer calculate the offset instead of re recalculate each time the freq_analysis
            caesar_key += ((O[(i + j) % 26] - E[j]) ** 2) / E[j]
        caesar_keys[i] = caesar_key
        caesar_key = 0

    return caesar_keys.index(min(caesar_keys))


def vigenere_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the ciphertext of <text> encrypted with Vigenere under key <key>
    """
    # TODO

    if not key.isalpha() or not key.isupper():
        raise Exception("Vigenere key must be only uppercase alpha char without accent and spaces")

    # Remove accent from text and key
    text = format_text(text)
    key = unidecode.unidecode(key)

    ciphertext = ""

    it = 0
    for c in text:
        # ord() give ASCII position of a char
        c_index = ord(c) - ord("A")  # ord("A") = 65

        # instead of generating a key the same size as the text,
        # we can iterate over the key with a key length modulo
        k_index = ord(key[it % len(key)]) - ord("A")

        it += 1

        ciphertext += shift_char_by_index(c_index, k_index)

    return ciphertext


def vigenere_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the plaintext of <text> decrypted with Vigenere under key <key>
    """
    # TODO
    # To factorize the code, we can call the function vigenere encrypt with an inverted key + 1.
    # This is equivalent to finding the opposite of an element of the additive group Z26 and adding 1 to the result

    if not key.isalpha() or not key.isupper():
        raise Exception("Vigenere key must be only uppercase alpha char without accent and spaces")

    # Remove accent from key
    key = unidecode.unidecode(key)

    reversed_key = key.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'AZYXWVUTSRQPONMLKJIHGFEDCB'))

    deciphertext = vigenere_encrypt(text, reversed_key)

    return deciphertext


def coincidence_index(text):
    """
    How it works
    ------------
    IT's the technique of putting two texts side-by-side and counting the number of times
    that identical letters appear in the same position in both texts.
    The index of coincidence provides a measure of how likely it is to draw two matching letters by randomly
    selecting two letters from a given text.

    French text
    -----------
    I get approximately 2.02 for a French IC

    Random text
    -----------
    I get approximately 8.02 for a random IC

    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    the index of coincidence of the text
    """
    # TODO

    count_vector = count_alpha_char_occurence(text)

    # Compute sum ni(ni-1)
    ICsum = 0
    for f in count_vector:
        ICsum += f * (f - 1)

    # dtype=np.float64 prevent overflow result
    text_len = np.sum(count_vector, dtype=np.float64)

    IC = (26 * ICsum) / (text_len * (text_len - 1))

    return IC


def vigenere_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break

    Returns
    -------
    the keyword corresponding to the encryption key used to obtain the ciphertext
    """
    # TODO

    formated_text = format_text(text)

    key_IC = [0] * 20
    text_with_key_size_offset = ""

    # Find the best key size
    for key_size in range(20):
        for i in range(len(formated_text)):
            pos = i + (i * key_size)
            if pos < len(formated_text):
                text_with_key_size_offset += formated_text[pos]

        key_IC[key_size] = coincidence_index(text_with_key_size_offset)
        text_with_key_size_offset = ""

    # Extract the index of the nearest IC to 2.02
    best_key_size = min(range(len(key_IC)), key=lambda k: abs(key_IC[k] - 2.02)) + 1

    columns = [0] * best_key_size
    current_column = ""

    # Format the text in a number of columns equals to the best key size
    for i in range(best_key_size):
        for j in range(len(formated_text)):
            index = i + (j * best_key_size)
            if index < len(formated_text):
                current_column += formated_text[index]
        columns[i] = current_column
        current_column = ""

    # Find the best corresponding letter for each column with the help of caesar break
    THE_KEY = ""
    for c in range(best_key_size):
        THE_KEY += chr(65 + caesar_break(columns[c]))

    return THE_KEY


def vigenere_caesar_encrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the ciphertext of <text> encrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    # TODO

    if not vigenere_key.isalpha() or not vigenere_key.isupper():
        raise Exception("Vigenere key must be only uppercase alpha char without accent and spaces")

    # Remove accent from key
    vigenere_key = unidecode.unidecode(vigenere_key)

    if not caesar_key.isdigit():
        raise Exception("Caesar key must be only digit")

    # Remove accent from key
    vigenere_key = unidecode.unidecode(vigenere_key)

    text = format_text(text)
    splited_text = [text[i:i + len(vigenere_key)] for i in range(0, len(text), len(vigenere_key))]

    ciphertext = ""

    for i in range(len(splited_text)):
        ciphertext += vigenere_encrypt(splited_text[i], vigenere_key)
        vigenere_key = caesar_encrypt(vigenere_key, caesar_key)

    return ciphertext


def vigenere_caesar_decrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to decrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the plaintext of <text> decrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    # TODO
    if not vigenere_key.isalpha() or not vigenere_key.isupper():
        raise Exception("Vigenere key must be only uppercase alpha char without accent and spaces")

    # Remove accent from key
    vigenere_key = unidecode.unidecode(vigenere_key)

    if not caesar_key.isdigit():
        raise Exception("Caesar key must be only digit")

    splited_text = [text[i:i + len(vigenere_key)] for i in range(0, len(text), len(vigenere_key))]

    deciphertext = ""

    for i in range(len(splited_text)):
        deciphertext += vigenere_decrypt(splited_text[i], vigenere_key)
        vigenere_key = caesar_encrypt(vigenere_key, caesar_key)

    return deciphertext


def vigenere_caesar_break(text):
    """
    Parameters
    ----------
    text: the ciphertext to break

    Returns
    -------
    pair
        the keyword corresponding to the vigenere key used to obtain the ciphertext
        the number corresponding to the caesar key used to obtain the ciphertext
    """
    # TODO you can delete the next lines if needed
    formated_text = format_text(text)

    vigenere_key = ""
    caesar_key = ""
    vigenere_key_length = 0
    best_ic = 0

    # There is the big deal of the lab. To find the best range of the vigenere key size,
    # we should do a top 10 key for each try of a specific range.
    # The value 16 works for the given vigenereAmleliore.txt file
    for viegener_key_size in range(1, 16):
        text_vigenere_offset = ""
        pos = len(formated_text) // viegener_key_size
        for i in range(pos):
            # As the vigenere tools, create specific text with a number of column equal to "viegener_key_size"
            text_vigenere_offset += formated_text[i * viegener_key_size]

        for current_caesar_key_size in range(26):
            text_caesar_offset = ""
            # Shift the specific text with each caesar offset
            for k in range(len(text_vigenere_offset)):
                text_caesar_offset += caesar_decrypt(text_vigenere_offset[k], current_caesar_key_size * k)

            current_coincidence_index = coincidence_index(text_caesar_offset)

            # Stock only the best IC index, and so, the best caesar and vigenere corresponding key
            if current_coincidence_index > best_ic:
                best_ic = current_coincidence_index
                caesar_key = current_caesar_key_size
                vigenere_key_length = viegener_key_size

    for i in range(vigenere_key_length):
        tmp_caesar = ""
        for j in range(len(text)):
            pos = i + (j*vigenere_key_length)
            if pos < len(text):
                # Create a specific text with a viegenere key size offset
                tmp_caesar += caesar_decrypt(text[pos], j*caesar_key)
        vigenere_key += chr(caesar_break(tmp_caesar)+65)

    return vigenere_key, caesar_key


def main():
    # Get universal frequencies (accessed only once for each execution)
    f_ref_g = open('gutenbergEBook.txt', 'r', encoding="utf8")
    global content_gutenbergEBook
    content_gutenbergEBook = f_ref_g.read()
    f_ref_g.close()

    print("Welcome to the Vigenere breaking tool")
    # TODO something
    print("**********************************")
    print("Caesar :")

    text_caesar = "la crypto c'est trop de la balle"
    key_caesar = 10

    print("Encryption of \"" + text_caesar + "\" with the key : " + str(key_caesar))
    ciphertext_caesar = caesar_encrypt(text_caesar, key_caesar)
    print("Encrypted text : " + ciphertext_caesar)
    best_key = caesar_break(ciphertext_caesar)
    print("Caesar break find " + str(best_key) + " for the best key")
    print("Try to decipher the text with the best key : " + caesar_decrypt(ciphertext_caesar, best_key))

    print("**********************************")
    print("Vigenere :")

    text_vigenere = "la crypto c'est trop de la balle"
    key_vigenere = "CRYPTO"

    print("Encryption of \"" + text_vigenere + "\" with the key : \"" + key_vigenere + "\"")
    ciphertext_vigenere = vigenere_encrypt(text_vigenere, key_vigenere)
    print("Encrypted text : " + ciphertext_vigenere)
    deciphertext_vigenere = vigenere_decrypt(ciphertext_vigenere, key_vigenere)
    print("Decipher the text with the key : " + "\"" + key_vigenere + "\" : " + deciphertext_vigenere)
    # print("Open the vigenere.txt file and try to find out the original key")
    # f_ref_v = open('vigenere.txt', 'r', encoding="utf8")
    # content_vigenere = f_ref_v.read()
    # f_ref_v.close()
    # original_key_vigenere = vigenere_break(content_vigenere)
    # print("Original key found : \"" + original_key_vigenere + "\"")
    # deciphertext_vigenere_with_original_key = vigenere_decrypt(content_vigenere, original_key_vigenere)
    # print("Try to decipher the text with the original key found : " + deciphertext_vigenere_with_original_key)

    print("**********************************")
    print("Vigenere caesar :")

    text_vigenere_caesar = "la crypto c'est trop de la balle"
    key_v_vigenere_caesar = "CRYPTO"
    key_c_vigenere_caesar = 2

    print("Encryption of \"" + text_vigenere_caesar + "\" with the vigenere key : \"" + key_v_vigenere_caesar + "\"" + " and the caesar key : " + str(key_c_vigenere_caesar))
    ciphertext_vigenere_caesar = vigenere_caesar_encrypt(text_vigenere_caesar, key_v_vigenere_caesar, key_c_vigenere_caesar)
    print("Encrypted text : " + ciphertext_vigenere_caesar)
    deciphertext_vigenere_caesar = vigenere_caesar_decrypt(ciphertext_vigenere_caesar, key_v_vigenere_caesar, key_c_vigenere_caesar)
    print("Decipher the text with the vigenere key : \"" + key_v_vigenere_caesar + "\"" + " and the caesar key : " + str(key_c_vigenere_caesar) + " : " + deciphertext_vigenere_caesar)
    print("Open the vigenereAmeliore.txt file and try to find out the two originals keys")

    f_ref_v_c = open('vigenereAmeliore.txt', 'r', encoding="utf8")
    content_vigenere_improved = f_ref_v_c.read()
    f_ref_v_c.close()

    original_key_v_vigenere_caesar, original_key_c_vigenere_caesar = vigenere_caesar_break(content_vigenere_improved)
    print("Original vigenere key found : \"" + original_key_v_vigenere_caesar + "\"")
    print("Original caesar key found : " + str(original_key_c_vigenere_caesar))
    deciphertext_vigenere_caesar_with_originals_keys = vigenere_caesar_decrypt(content_vigenere_improved, original_key_v_vigenere_caesar, original_key_c_vigenere_caesar)
    print("Try to decipher the text with the original key found : " + deciphertext_vigenere_caesar_with_originals_keys)


if __name__ == "__main__":
    main()
