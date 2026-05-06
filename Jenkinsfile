pipeline {
    agent any

    stages {

        stage('Build Docker Image') {
            steps {
                sh 'docker build -t password-app .'
            }
        }

        stage('Run Container') {
            steps {
                sh '''
                docker stop password-app-container || true
                docker rm password-app-container || true
                docker run -d -p 5000:5000 --name password-app-container password-app
                '''
            }
        }
    }
}