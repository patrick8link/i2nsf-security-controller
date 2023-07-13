<!-- Improved compatibility of back to top link: See: https://github.com/othneildrew/Best-README-Template/pull/73 -->
<a name="readme-top"></a>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

<!-- PROJECT LOGO -->
<br />
<div align="center">

  <h1 align="center">I2NSF Security Controller</h1>

  <p align="center">
    A Proof-of-Concept Implementation for I2NSF
    <br />
    <a href="https://www.youtube.com/watch?v=OWNJbF7wGgs&ab_channel=PatrickLingga">View Demo</a>
    ·
    <a href="https://github.com/patrick8link/i2nsf-security-controller/issues">Report Bug</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project
![GUI Screen Shot](https://github.com/patrick8link/i2nsf-security-controller/blob/1.1/GUI.png)

Security Controller is a key component of the I2NSF framework that is responsible for managing and orchestrating the network security functions. It acts as a central entity that receives high-level rule sets and translates them into low-level configurations that can be understood and implemented by the NSFs. It also selects the NSFs that can apply the security requirements by selecting the NSFs with appropriate capabilities.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- GETTING STARTED -->
## Getting Started

There are three important directories in the security controller:
* API: provides the security policy translation for translating high-level security policy to low-level security policy.
* react: provides the GUI for I2NSF User.
* analytics: provides analytics interface with ConfD.

### Prerequisites

A freshly installed Ubuntu 20.04 LTS.
Get ConfD developed by Cisco tail-f [here](https://developer.cisco.com/site/confD/)


### Installation

_Below is an example of how you can instruct your audience on installing and setting up your app. This template doesn't rely on any external dependencies or services._


1. Clone the repo
   ```sh
   git clone https://github.com/patrick8link/i2nsf-security-controller/ -b 1.1
   ```
2. Install confd - For more information access [ConfD Kick Start Guide](https://info.tail-f.com/confd-evaluation-kick-start-guide)
   ```sh
   sudo apt install unzip libxml2-utils python3-pip subversion
   unzip confd-basic-8.0.4.linux.x86_64.zip
   sudo ln -s /usr/bin/python3 /usr/bin/python
   sh confd-basic-8.0.4.linux.x86_64.signed.bin
   sh confd-basic-8.0.4.linux.x86_64.installer.bin ~/confd
   python -m pip install paramiko configparser
   ```
3. Install the packages
   ```sh
   sudo apt update
   ./install.sh
   ./mongo.sh
   ```
4. Run mongo daemon and make sure MongoDB is running
   ```sh
   sudo systemctl start mongod
   sudo systemctl status mongod
   ```
5. Insert initial data to MongoDB
   ```sh
   cd ~/i2nsf-security-controller/API
   python3 insertMongoDB.py
   ```
6. Update **controller.ini** with the correct IP addresses
   ```sh
   [DEFAULT]
   Controller = #FLOATING IP address of Controller
   PrivateController = #Private IP address of Controller
   DMS = #Floating IP address of DMS
   PrivateDMS = #Private IP address of DMS
   ```
7. Run **setup.sh**
   ```sh
   ./setup.sh
   ```
8. Install npm packages
   ```sh
   cd ~/i2nsf-security-controller/react
   npm i
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- USAGE EXAMPLES -->
## Usage

1. Run the GUI
   ```sh
   cd ~/i2nsf-security-controller/react
   npm start
   ```
2. Open a new terminal and run the Translator API
   ```sh
   cd ~/i2nsf-security-controller/API
   python3 RestAPI.py [--ip <ip-address>|--if <interface-name>]
   ```
3. Open a new terminal and run the analytics interface
   ```sh
   source ~/confd/confdrc
   cd ~/i2nsf-security-controller/analytics
   make clean all start
   ```
_For more examples, please refer to the [Documentation](https://example.com)_

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

Patrick Lingga - https://patrick8link.github.io/

Project Link: [https://github.com/patrick8link/i2nsf-security-controller/tree/1.1](https://github.com/patrick8link/i2nsf-security-controller/tree/1.1)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
<!-- 
## Acknowledgments

Use this space to list resources you find helpful and would like to give credit to. I've included a few of my favorites to kick things off!

* [Choose an Open Source License](https://choosealicense.com)
* [GitHub Emoji Cheat Sheet](https://www.webpagefx.com/tools/emoji-cheat-sheet)
* [Malven's Flexbox Cheatsheet](https://flexbox.malven.co/)
* [Malven's Grid Cheatsheet](https://grid.malven.co/)
* [Img Shields](https://shields.io)
* [GitHub Pages](https://pages.github.com)
* [Font Awesome](https://fontawesome.com)
* [React Icons](https://react-icons.github.io/react-icons/search)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
-->


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/othneildrew/Best-README-Template.svg?style=for-the-badge
[contributors-url]: https://github.com/othneildrew/Best-README-Template/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/othneildrew/Best-README-Template.svg?style=for-the-badge
[forks-url]: https://github.com/othneildrew/Best-README-Template/network/members
[stars-shield]: https://img.shields.io/github/stars/othneildrew/Best-README-Template.svg?style=for-the-badge
[stars-url]: https://github.com/othneildrew/Best-README-Template/stargazers
[issues-shield]: https://img.shields.io/github/issues/othneildrew/Best-README-Template.svg?style=for-the-badge
[issues-url]: https://github.com/othneildrew/Best-README-Template/issues
[license-shield]: https://img.shields.io/github/license/othneildrew/Best-README-Template.svg?style=for-the-badge
[license-url]: https://github.com/othneildrew/Best-README-Template/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/othneildrew
[product-screenshot]: GUI.png
[Next.js]: https://img.shields.io/badge/next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white
[Next-url]: https://nextjs.org/
[React.js]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB
[React-url]: https://reactjs.org/
[Vue.js]: https://img.shields.io/badge/Vue.js-35495E?style=for-the-badge&logo=vuedotjs&logoColor=4FC08D
[Vue-url]: https://vuejs.org/
[Angular.io]: https://img.shields.io/badge/Angular-DD0031?style=for-the-badge&logo=angular&logoColor=white
[Angular-url]: https://angular.io/
[Svelte.dev]: https://img.shields.io/badge/Svelte-4A4A55?style=for-the-badge&logo=svelte&logoColor=FF3E00
[Svelte-url]: https://svelte.dev/
[Laravel.com]: https://img.shields.io/badge/Laravel-FF2D20?style=for-the-badge&logo=laravel&logoColor=white
[Laravel-url]: https://laravel.com
[Bootstrap.com]: https://img.shields.io/badge/Bootstrap-563D7C?style=for-the-badge&logo=bootstrap&logoColor=white
[Bootstrap-url]: https://getbootstrap.com
[JQuery.com]: https://img.shields.io/badge/jQuery-0769AD?style=for-the-badge&logo=jquery&logoColor=white
[JQuery-url]: https://jquery.com 
