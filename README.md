Python script to list udemy.com courses subscribed in an account. 

### Version
**0.1-alpha**

### Prerequisites

* Python (2 or 3)
* `pip` (Python Install Packager)
* Python module `requests`
  * If missing, they will be automatically installed by `pip`


### Preinstall

If you don't have `pip` installed, look at their [install doc](http://pip.readthedocs.org/en/latest/installing.html).
Easy install (if you trust them) is to run their bootstrap installer directly by using: `sudo curl https://bootstrap.pypa.io/get-pip.py | sudo python`

### Running Instructions on OS X/Linux

1.  Clone or download repo. 
2. Browse to directory and install requirements `sudo -H pip install -r requirements.txt`
3. Run script `python udemy-list -u <user-name> -p <password>  --debug -ps 200 -mp 0`

`udemy-list` was made by using [udemy-dl](https://github.com/nishad/udemy-dl) as base project and stripping away unneeded code.
