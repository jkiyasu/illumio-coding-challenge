# illumio-coding-challenge

a. I tested my solution with the given test cases, which it initially failed, but later passed when I fixed my type errors. I also realized that ip addresses would not be properly compared if I left them as strings, so I converted them to lists of ints for correct comparison. Upon reflection, I definitely should've budgeted more time for testing. Some good test cases would be using a csv file that has many more rules (>=500k) to test for time efficiency using time.time(), testing for proper construction of ranges, proper comparison of port and ip_address ranges, and testing proper merging of rules (if I had implemented merging, it should both choose what to merge correctly and merge correctly). For choosing what to merge, it should only merge rules that share the same direction, protocol, and overlap in both port and ip_address ranges. 

b. At first I was very stuck on how to make the function work quickly, because the naive solution is just to check all the rules one by one, but I knew that to save on time complexity, I wanted to pre-calculate as much as I could inside the constructor function. I finally realized that I could break down the initial csv into 4 categories (since direction and protocol each only take on 2 values) so I created a pandas dataframe to filter the table by direction and protocol. I also decided that I wanted to convert all rules's port and ip_address values to ranges in order to simplify the number of cases I have to deal with.

c. Given more time, I was planning to improve my time complexity by merging rules with overlapping ranges so there would be less iteration to do (I would implement this using a variation of my merge_intervals function). I would also have this new list of rules be sorted by starting port range, and then by starting ip address (within the constructor function) so that I could do some sort of binary search to check for the set of rules that this package's port fits in. And then within that set of rules (which should be sorted by ip_address due to constructor), I could use a similar method to check for the set of rules that this package's ip_address fits in, and if that's non-empty, return True. I would have to be careful, however, to make sure ip_addresses were compared correctly when sorting. 

I also would spend more time thinking about how to optimize the space complexity given the constraint that we need to check incoming and outgoing packages quickly even for a million rules. We could store a number of rules less than the given number of rules if there is overlapping information, but you need to initially store all the rules before merging.

I would also make better use of the internet as a resource for aspects of this problem, because I definitely under-utilized the internet by sticking to basic questions such as "how to read csv python". I was sort of afraid to ask questions more specific to the problem cause it felt like cheating even though I  I was encouraged to use all the resources at my disposal besides other people so I shouldn't have let that affect me. 

I am interested in the Data team (first choice) and Policy team (second choice)
