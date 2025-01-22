## How to run the application?
- **Ensure JDK 21 or a later version installed** as this application is configured with that version. If you haven't 
  installed it yet, follow [this link](#how-to-install-jdk-21-or-a-later-version) for installation instruction.
- To start the application, navigate to the project root directory and run `./gradlew run` in your terminal.
  This will launch the application with the default input/output files:
  - `input=input.txt`
  - `output=output.txt`
  - `lookup=lookup.txt`
- To override the default input/output files, run `./gradlew run --args='-i <inputFilePath> -o <outputFilePath> -l <lookupFilePath>'`
  e.g `./gradlew run --args='-i input.txt -o output.txt -l lookup.txt`

## What is Cyberelay?
- **Cyberelay** was a name I created for my Web Portal Server project about 20 years ago, though the project
  itself never gained traction. The main outcome of this endeavor was registering the domains `cyberelay.com` and
  `cyberelay.org`. Over the years, I've primarily used Cyberelay for Java package naming in my hobby projects.

## How to Review the Code?
- This application is a Spring Boot project which was initiated by using [Spring initializer](https://start.spring.io/).
- The application consists of two main components:
  - `LogAnalyzerApplication` -- A spring powered CLI application
  - `LogStatsCollector` -- A service that analyzes the logs and collects the stats.

## Misc

#### How to Install JDK 21 or a Later Version?
- You can follow the instructions on the [SDKMAN! website](https://sdkman.io/) to install the JDK.
