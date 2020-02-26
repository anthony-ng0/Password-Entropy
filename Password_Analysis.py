'''

Algorithm:
    Call the main function
        Initialize the banner and menu and print those statements
        Prompt for a user choice
        Use while loop to reprompt if the choice is invalid
        If choice == 1
            Prompt for password and hash files
            Call the open_file function to open these files 
            Call the build_password_dictionary to to store info from the
            password file
            Call the cracking function to determine which passwords from the
            password dictionary have been "cracked"
            Print the passwords and it's data using formatted print statements
            Reprompt for choice
        If choice == 2
            Prompt for password and hash files
            Call the open_file function to open these files
            Prompt for word,name and phrase files
            Call the open_file function to open these files
            Call the build_pass_word dictionary to store info 
            Call the common_patterns function to determine word patters
            within the password dictionary
            Print the passwords and the patterns in a specific format
            Reprompt for choice
        If choice == 3
            Prompt for password
            Call the password_entropy_calculator to determine entropy
            of the password
            Reprompt for choice
        If choice == 4:
            Quitmost
'''

from math import log2
from operator import itemgetter
from hashlib import md5
from string import ascii_lowercase, ascii_uppercase, digits, punctuation

def open_file(message):
    '''
    Prompt for a file name
    Use while loop and try-except format to ensure a valid file name
    If the input is empty, the default file will be "pass.txt"
    Returns: file pointer
    '''
    #Prompt for file name
    #While loop to ensure a continous cycle of file inputs
    while True:
        #If there is a FileNotFoundError, it will reprompt
        try:
            #"pass.txt" will be default file is input in empty
            if message == "":
                message = "pass.txt"
            fp = open(message)
            return fp
        except FileNotFoundError:
            print("File not found. Try again.")
            message = input("Input a file name: ")
            
def check_characters(password, characters):
    '''
    Loops through the password's characters using for loop
         If a character is in the inputted character string
             Returns: True
    else:
        The character is not in the inputted character string
        Returns: False
    '''
    #Loops through characters in password
    for i in password:
        #Checks if character is in characters
        if i in characters:
            return True
    else:
        return False

def password_entropy_calculator(password):
    '''
    Takes in a password string as an argument
    Uses try-except to determine the entropy of the password with 
    entropy = L*log2(N)
    Calculates the length of the password for L
    Calls the check_characters function with the password and various inputs
    to determine the N value
    Uses if else statements to check the values of the check_characters
    functions to determine N value
    Calculates entropy and rounds it to 2 decimal places
    Returns: The entropy float
    '''
    #Calculates length of password
    L = len(password)
    #Default N value is 0
    N= 0
    #Calls the check_characters functions with the password and characters to
    #compare it to
    check_lower = check_characters(password, ascii_lowercase)
    check_upper = check_characters(password, ascii_uppercase)
    check_digits = check_characters(password, digits)
    check_punctuation = check_characters(password, punctuation)
    #Returns 0 if the password string is empty
    if password == "":
        return 0
    #Uses various if statements to check the values of the check_characters
    #functions to determine the N value
    if check_lower == False and check_upper == False and check_digits == True and check_punctuation == False:
        N= 10
    if check_lower == False and check_upper == False and check_digits == False and check_punctuation == True:
        N = 32
    if check_lower == False and check_upper == False and check_digits == True and check_punctuation == True:
        N = 42
    if check_lower == True and check_upper == False and check_digits == False and check_punctuation == False:
        N = 26
    if check_lower == False and check_upper == True and check_digits == False and check_punctuation == False:
        N = 26
    if check_lower == True and check_upper == True and check_digits == False and check_punctuation == False:
        N = 52
    if check_lower == True and check_upper == False and check_digits == True and check_punctuation == False:
        N = 36
    if check_lower == False and check_upper == True and check_digits == True and check_punctuation == False:
        N = 36
    if check_lower == False and check_upper == True and check_digits == False and check_punctuation == True:
        N = 58
    if check_lower == True and check_upper == False and check_digits == False and check_punctuation == True:
        N = 58
    if check_lower == True and check_upper == True and check_digits == True and check_punctuation == False:
        N = 62
    if check_lower == True and check_upper == True and check_digits == False and check_punctuation == True:
        N = 84
    if check_lower == True and check_upper == True and check_digits == True and check_punctuation == True:
        N = 94
    if check_lower == True and check_upper == False and check_digits == True and check_punctuation == True:
        N = 68
    if check_lower == False and check_upper == True and check_digits == True and check_punctuation == True:
        N = 68
    #Uses try-except to calculate the entropy with the given formula
    try:
        entropy = L * (log2(N))
        entropy_flt = round(entropy,2)
        return entropy_flt
    except ValueError:
        pass
   
def build_password_dictionary(fp):
    '''
    Builds a password dictionary that composes of it's md5 pash, rank
    and entropy
    Uses for loop to iterate through the file
        Increase the rank by 1 through each iteration
        Use the md5 method to create the hash for the password
        Call the password_entropy_calculator function to find the entropy
        Append the rank,password and entropy to a list and convert to tuple
        Create a dictionary with the hash as a key and the tuple as the value
    Returns: The password dictionary
    '''
    #Initializes values
    rank = 0
    password_dict = {}
    #Uses for loop to iterate through the file
    for line in fp:
        password_data_list = []
        #Increase rank by 1 with each iteration
        rank += 1
        password = line.replace("\n","")
        #Create the password hash
        p_hash = md5(password.encode()).hexdigest()
        #Calculate entropy with the function
        entropy = password_entropy_calculator(password)
        #Append values toa list
        password_data_list.append(password)
        password_data_list.append(rank)
        password_data_list.append(entropy)
        password_data_tuple = tuple(password_data_list)
        #Create a dictionary with the hash as key and tuple as value
        password_dict[p_hash] = password_data_tuple
    return password_dict
    
def cracking(fp,hash_D):
    '''
    Uses for loop to iterate through each line in the file
        Uses split method to isolate the hash
        Iterate through the items in the password dictionary
            if the key password dictionary equals the hash in the file
                The password is "cracked"
                Data from the password dictionary is appended to a list
                The password_list is converted to a tuple
                The password_tuple is appended to a final_list
        The number of cracked and uncracked passwords is then appended
        to the final list
    Returns: The final list with the cracked password data and the number
    of cracked and uncracked passwords
    '''
    #Initializes values
    cracked_list = []
    cracked_int = 0
    uncracked_int = 0
    counter = 0
    final_list = []
    #Iterates through each line in the file
    for line in fp:
        counter += 1
        password_list = []
        #Splits the line between the hash and the hex
        line_list = line.split(":")
        #Isolates the password hash
        p_hash = line_list[0]
        #Iterates through the items in the password dictionary
        for key,value in hash_D.items():
            #If the hash equals the key in the password dictionary
            if key == p_hash:
                #Isolates the entropy
                entropy = value[2]
                #Appends the values to a password_list
                password_list.append(p_hash)
                password_list.append(value[0])
                password_list.append(entropy)
                #Converts the list to a tuple
                password_tuple = tuple(password_list)
                #Appends the tuple to a larger list
                cracked_list.append(password_tuple)
                #Counts the cracked passowrds
                cracked_int += 1
    #Calculates uncracked passwords
    uncracked_int = counter - cracked_int       
    cracked_list.sort(key=itemgetter(1))    
    #Appends values to a final list
    final_list.append(cracked_list)
    final_list.append(cracked_int)
    final_list.append(uncracked_int)
    return final_list    
    
def create_set(fp):  
    '''Read file and return data as a set'''
    password_list = []
    #Iterates through each line in the file
    for line in fp:  
        #Removes the carriage returns
        line = line.replace("\n","")
        #Appends the words to a list
        password_list.append(line)
    password_set = set(password_list) 
    return password_set

def common_patterns(D,common,names,phrases):
    '''
    Iterates through each value in the password dictionary using for loop
        Isolates password and changes it to lowercase
        Iterates through each word in the common_set
            Lowercases the word
            Uses if statement to check if the word is in the password to 
            detect patterns
                Appends the phrase to a list if it's in the password
        Iterates through each name in the names_set
            Lowercases the name
            Uses if statement to check if the name is in the password to 
            detect patterns
                Appends the phrase to a list if it's in the password
        Iterates through each phrase in the phrases_set
            Lowercases the phrase
            Uses if statement to check if the phrase is in the password to 
            detect patterns
                Appends the phrase to a list if it's in the password
        Sorts the pattern_list
        #Create a dictionary with the password as the key and the list as value
        Returns: the pattern_dictionary
        
    '''
    pattern_dict = {}
    #Iterates through each value in the password dictionary
    for value in D.values():
        pattern_list = []
        #Isolates the password and lowercases it
        password = value[0].lower()
        #Iterates through each set
            #Uses if statement to see if the word is in the passowrd
            #If the word is in the password, append it to a list
        for word in common:
            word= word.lower()
            if word in password:
                pattern_list.append(word)
        for name in names:
            name = name.lower()
            if name in password:
                pattern_list.append(name)
        for phrase in phrases:
            phrase = phrase.lower()
            if phrase in password:
                pattern_list.append(phrase)    
        #Convert list to a set and back to a list
        pattern_set = set(pattern_list)
        pattern_revised= list(pattern_set)
        #Sort the list
        pattern_revised.sort()
        #Create a dictionary with the password as the key and the list as value
        pattern_dict[password] = pattern_revised
    return pattern_dict
        
def main():
    '''
    Initialize the banner and menu and print them
    Prompt for a user choice
    Use while loop to reprompt if the choice is invalid
        If choice == 1
            Prompt for password and hash files
            Call the open_file function to open these files 
            Call the build_password_dictionary to to store info from the
            password file
            Call the cracking function to determine which passwords from the
            password dictionary have been "cracked"
            Print the passwords and it's data using formatted print statements
            Reprompt for choice
        If choice == 2
            Prompt for password and hash files
            Call the open_file function to open these files
            Prompt for word,name and phrase files
            Call the open_file function to open these files
            Call the build_pass_word dictionary to store info 
            Call the common_patterns function to determine word patters
            within the password dictionary
            Print the passwords and the patterns in a specific format
            Reprompt for choice
        If choice == 3
            Prompt for password
            Call the password_entropy_calculator to determine entropy
            of the password
            Reprompt for choice
        If choice == 4:
            Quit
    Returns: None
    '''
    
    BANNER = """
       -Password Analysis-

          ____
         , =, ( _________
         | ='  (VvvVvV--'
         |____(

    """

    MENU = '''
    [ 1 ] Crack MD5 password hashes
    [ 2 ] Locate common patterns
    [ 3 ] Calculate entropy of a password
    [ 4 ] Exit

    [ ? ] Enter choice: '''
    
    print(BANNER)
    print(MENU)
    #Prompt for input
    choice = input("")
    #Use while loop to remprompt if the choice is invalid
    while choice != "1" and choice != "2" and choice != "3" and choice != "4":
        print('Error. Try again.')
        print(MENU)
        choice = input("")
    #If the choice input is equal to 1
    if choice == "1":
        #Prompt for password file
        message = input('Common passwords file [enter for default]: ')
        #Open the file using open_file function
        fp = open_file(message)
        #Prompt for hash file
        hash_message = input('Hashes file: ')
        #Open the file using open_fule function
        fp1 = open_file(hash_message)
        #Build a password dictionary using the function
        password_dict = build_password_dictionary(fp)
        #Create a list of cracked passwords using the cracking function
        cracking_list = cracking(fp1,password_dict)
        cracking_sub_list = cracking_list[0]
        print("\nCracked Passwords:")
        #For the tuple within the cracking list
        for pass_tuple in cracking_sub_list:
            #Print out formatted password data
            print('[ + ] {:<12s} {:<34s} {:<14s} {:.2f}'.format("crack3d!",pass_tuple[0],pass_tuple[1],pass_tuple[2]))
        print('[ i ] stats: cracked {:,d}; uncracked {:,d}'.format(cracking_list[1],cracking_list[2]))
        fp.seek(0)
        fp1.seek(0)
        #Reprompt
        print(MENU)
        choice = input("")
    #If the choice input is equal to 2
    if choice == "2":
        #Prompt for password file
        message = input('Common passwords file [enter for default]: ')
        #Use open_file function to open the file
        fp = open_file(message)
        #Build a password dictionary using the function
        password_dict = build_password_dictionary(fp)
        #Prompt for word file and use open_file function
        word_file = input("Common English Words file: ")
        fp2 = open_file(word_file)
        #Create a set with the word file using create_set function
        common_words_set = create_set(fp2)
        #Prompt for name file and use open_file function
        name_file = input("First names file: ")
        fp3 = open_file(name_file)
        #Create a set with the name file using create_set function
        common_names_set = create_set(fp3)
        #Prompt for phrase file and use open_file function
        phrase_file = input("Phrases file: ")
        fp4 = open_file(phrase_file)
        #Create a set with the phrase file using create_set function
        common_phrases_set = create_set(fp4)
        #Use common_patterns function to create a pattern dictionary
        patterns_dict = common_patterns(password_dict, common_words_set,common_names_set,common_phrases_set)
        print("\n{:20s} {}".format("Password","Patterns"))
        #loop through the items in the patterns dictionary and print values
        for k,v in patterns_dict.items():
            print("{:20s} [".format(k),end='')# print password
            print(', '.join(v),end=']\n') # print comma separated list
        fp.seek(0)
        fp2.seek(0)
        fp3.seek(0)
        fp4.seek(0)
        #Reprompt
        print(MENU)
        choice = input("")
    #If the choice input is equal to 3
    if choice == "3":
        #Prompt for password to be used to calculate entropy
        password_input = input('Enter the password: ')
        #Call the entropy function to calculate the entropy
        entropy = password_entropy_calculator(password_input)
        #Print out the entropy value using a format
        print('The entropy of {} is {}'.format(password_input,entropy))
        #Reprompt
        print(MENU)
        choice = input("")
    #If the choice input is equal to 4
    if choice == "4":
        #Passes so the program ends
        pass
#Calls the main function
if __name__ == '__main__':
    main()