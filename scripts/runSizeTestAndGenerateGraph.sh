set -x
#this script is used in Jenkings jobs to check size of bootloader and to generate graphical presentation of binary
mbed compile -m K64F -t GCC_ARM --profile=tiny.json | tee buildLog
# assuming there is only one string with Image: at the and following directly with created image
# like Image: ./BUILD/K64F/GCC_ARM-TINY/mbed-bootloader-internal.bin
imageFile=$(cat buildLog | grep Image: | cut -d ' ' -f 2)
echo $imageFile
echo $(stat --printf="%s" $imageFile) | tee BINSIZE # current build size
git clone https://github.com/ARMmbed/mbed-os-linker-report.git --depth 1
fileWithouEnd=$(echo $imageFile | cut -d '.' -f 2)
python mbed-os-linker-report/elfsize.py -i .$fileWithouEnd.elf
maxSize=32768
currentBinSize=77777777 # just so that we will fail for sure later for size check
currentBinSize=$(cat BINSIZE)
# zip the results for local use as the Jenkings iframe does not allow external load (D3 module fails). 
# Maybe access will be relaxed later and this step becomes obsolete
tar -zcvf USE_THIS_IF_JENKINGS_INDEX_HTML_DOES_NOT_LOAD.tar.gz mbed-os-linker-report/html/ mbed-os-linker-report/index.html
mv USE_THIS_IF_JENKINGS_INDEX_HTML_DOES_NOT_LOAD.tar.gz mbed-os-linker-report/
if [ $currentBinSize -le $maxSize ]; then
	echo "BINARY SIZE ok (max $maxSize current $currentBinSize)"
	exit 0
else
	echo "error BINARY SIZE TOO LARGE max $maxSize current $currentBinSize"
	exit 1
fi