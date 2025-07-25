STEP 0: Calculate the DLL's current base address
STEP 1: Process the kernels exports for the functions our loader needs
STEP 2: Load our image into a new permanent location in memory
STEP 3: Load in all of our sections
STEP 4: Process DLL image's import table
STEP 5: Process all of DLL image's relocations
STEP 6: Call the DLL entry point