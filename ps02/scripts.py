"""
Scripts to calculate averages of number of configurations to signatures
"""


global_dict = {}
global_list = []

def scripts(file):
    length = 0
    with open(file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            line = line.split(':')
            line[1] = line[1].split('], [')
            global_dict[line[0]] = len(line[1])
            length += len(line[1])
            
    
    total = len(global_dict.keys())
    while len(global_dict.keys()) != 0:
        largest = 0
        largest_key = ''
        for key in global_dict.keys():
            if global_dict[key] > largest:
                largest = global_dict[key]
                largest_key = key
        global_list.append(str(largest) + ':' + largest_key)
        del global_dict[largest_key]

    for ele in global_list:
        print(ele)
    print("average : ", length/total)
    print(length)

def main():
    file = 'sig_to_config.txt'
    scripts(file)

if __name__ == "__main__":
    main()