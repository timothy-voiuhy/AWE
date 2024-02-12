list1 = [1, 2, 3]
list2 = ['a', 'b', 'c']
list3 = [10, 20, 30]

zipped_lists = zip(list1, list2, list3)


# this works if we are going to use the first value of list1, the first value of list2 and the first value of list3 
for item in zipped_lists:
    print(item)
