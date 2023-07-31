# Croxe
### A simple photo injection and extraction tool

![Screenshot_2023-07-31_20-28-03](https://github.com/MASTAR-LAST/Croxe/assets/79379000/e3d53f29-33ae-48e2-a7f5-829874875f5a)


# Installation

### make a clone 
```bash
git clone https://github.com/MASTAR-LAST/Croxe.git
```

### go to tool file
```bash
cd Croxe
```

### start injecting
```bash
python3 croxe.py -h
```

### Help guide

```
usage: python3 croxe.py [-h] [-D DATA] [-H HASH_TYPE] [-e] [-d] [-i] [-f] [-b] [-c] target

Photo Injection Tool

positional arguments:
  target                the image that holding the data

options:
  -h, --help            show this help message and exit
  -D DATA, --data DATA  the data that will be inject in the target image
  -H HASH_TYPE, --hash-type HASH_TYPE
                        specific hash type for the data (Default = sha1)
  -e, --encrypt         data encrypt before injecting it (Default = false)
  -d, --decrypt         data decrypt after extracting it (Default = false)
  -i, --inject          choose to inject data instead of extracting it (Default = false)
  -f, --file            determine whether you are content inside a specific file (Default = false)
  -b, --back-up         take a back up for the source image in Form ^ImageName_backup.jpg^ (Default = false)
  -c, --clear           remove the injecting data from the target image [work just with the data that have been
                        injecting with the same tool in the same device]

Only JPG images is allowed

```

## Examples

### Read the injecting data
```bash
python3 croxy.py <imageName.jpg>
```

### Image injection
```bash
python3 croxy.py <imageName.jpg> --inject --data <your data>
```

### Image injection and encrypt the data before it
```bash
python3 croxy.py <imageName.jpg> --inject --data <your data> --encrypt
```

### Read the injecting data and decrypt the data
```bash
python3 croxy.py <imageName.jpg> --decrypt
```

### delete the injecting data
```bash
python3 croxy.py <imageName.jpg> --clear
```

### Image injection, encrypt the data and take a copy from the source image 
```bash
python3 croxy.py <imageName.jpg> --inject --data <your data> --back-up
```