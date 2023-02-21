pipeline {
    parameters {
      choice(name: 'action', choices: 'create\ndestroy', description: 'Create/update or destroy the eks cluster.')
      string(name: 'cluster', defaultValue: 'demo', description: "EKS cluster name.")
      choice(name: 'k8s_version', choices: '1.23\n1.22\n1.22', description: 'K8s version to install.')
      string(name: 'vpc_network', defaultValue: '10.0', description: "First 2 octets of vpc network; eg 10.0")
      string(name: 'num_subnets', defaultValue: '3', description: "Number of vpc subnets/AZs.")
      string(name: 'instance_type', defaultValue: 'm5.large', description: "k8s worker node instance type.")
      string(name: 'num_workers', defaultValue: '2', description: "k8s number of worker instances.")
      string(name: 'max_workers', defaultValue: '10', description: "k8s maximum number of worker instances that can be scaled.")
      string(name: 'admin_users', defaultValue: '', description: "Comma delimited list of IAM users to add to the aws-auth config map.")
      string(name: 'credential', defaultValue: 'AKIAVQEAISFXMZ4TTQHE', description: "Jenkins credential that provides the AWS access key and secret.")
      string(name: 'key_pair', defaultValue: 'cleterraformJenkins', description: "EC2 instance ssh keypair.")
      booleanParam(name: 'cw_logs', defaultValue: true, description: "Setup Cloudwatch logging?")
      booleanParam(name: 'cw_metrics', defaultValue: false, description: "Setup Cloudwatch metrics and Container Insights?")
      booleanParam(name: 'metrics_server', defaultValue: true, description: "Setup k8s metrics-server?")
      booleanParam(name: 'dashboard', defaultValue: false, description: "Setup k8s dashboard?")
      booleanParam(name: 'prometheus', defaultValue: true, description: "Setup k8s prometheus?")
      booleanParam(name: 'nginx_ingress', defaultValue: true, description: "Setup nginx ingress and load balancer?")
      booleanParam(name: 'ca', defaultValue: false, description: "Setup k8s Cluster Autoscaler?")
      booleanParam(name: 'cert_manager', defaultValue: false, description: "Setup cert-manager for certificate handling?")
      string(name: 'region', defaultValue: 'eu-west-1', description: "AWS region.")
    }
    options {
      skipDefaultCheckout()
      disableConcurrentBuilds()
      timeout(time: 1, unit: 'HOURS')
      withAWS(credentials: params.credential, region: params.region)
      ansiColor('vga')
    }
    agent any
    tools {
      terraform 'terraform-11'
    }
    environment {
      registry = "rajhisaifeddine/demo"
      registryCredential = 'rajhisaifeddine'
      dockerImage = ''
      dockerPush = ''
      PATH = "${env.WORKSPACE}/bin:${env.PATH}"
      KUBECONFIG = "${env.WORKSPACE}/.kube/config"
      NEXUS_VERSION = "nexus3"
      NEXUS_PROTOCOL = "http"
      NEXUS_URL = "xx.xx.xx.xx:10680"
      NEXUS_REPOSITORY = "maven-snapshots"
      NEXUS_CREDENTIAL_ID = "nexus-credentials"
      SONARQUBE_URL = "http://xx.xx.xx.xx"
      SONARQUBE_PORT = "9000"
    }
    stages {
      stage('SCM') {
        steps {
          checkout scm
        }
      }
  
      stage('Build mvn') {
        parallel {
          stage('Install') {
            agent {
              docker {
                image 'maven:3.6.0-jdk-8-alpine'
                args ' -v /root/.m2/repository:/root/.m2/repository'
                reuseNode true
              }
            }
            steps {
              sh 'mvn -B -DskipTests clean install'
            }
          }
          stage('CheckStyle') {
            agent {
              docker {
                image 'maven:3.6.0-jdk-8-alpine'
                args '-v /root/.m2/repository:/root/.m2/repository'
                reuseNode true
              }
            }
            steps {
  
              sh 'mvn --batch-mode -V -U -e checkstyle:checkstyle pmd:pmd pmd:cpd findbugs:findbugs com.github.spotbugs:spotbugs-maven-plugin:3.1.7:spotbugs'
            }
  
          }
  
        }
  
      }
  
      stage('Unit Tests') {
        agent {
          docker {
            image 'maven:3.6.0-jdk-8-alpine'
            args '-v /root/.m2/repository:/root/.m2/repository'
            reuseNode true
          }
        }
        steps {
          sh 'mvn test'
        }
  
      }
  
      stage('Integration Tests') {
        agent {
          docker {
            image 'maven:3.6.0-jdk-8-alpine'
            args '-v /root/.m2/repository:/root/.m2/repository'
            reuseNode true
          }
        }
        steps {
          sh 'mvn verify -Dsurefire.skip=true'
        }
        post {
          success {
            stash(name: 'artifact', includes: 'target/*.war')
            stash(name: 'pom', includes: 'pom.xml')
            // to add artifacts in jenkins pipeline tab (UI)
            archiveArtifacts 'target/*.war'
          }
        }
      }
  
      stage('Building and scanning ddocker image') {
        steps {
          script {
            sh """
            curl -sfL https: //raw.githubusercontent.com/aquasecurity/trivy/master/contrib/install.sh | sh -s -- -b ./bin
            if [!-f "html.tpl"];then
              wget https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/html.tpl
            fi
            """
            dockerImage = docker.build registry + ":$BUILD_NUMBER"
            sh """
            ./bin/trivy image --format template --template "@html.tpl" --output trivy_report.html "$registry"":$BUILD_NUMBER"
            """
          }
        }
  
        post {
          always {
            archiveArtifacts artifacts: "trivy_report.html", fingerprint: true
  
            publishHTML(target: [
              allowMissing: false,
              alwaysLinkToLastBuild: false,
              keepAll: true,
              reportDir: '.',
              reportFiles: 'trivy_report.html',
              reportName: 'Trivy Scan',
            ])
          }
        }
      }
  
      stage('Deploy Image to dockerhub') {
        steps {
          script {
            docker.withRegistry('', registryCredential) {
              dockerImage.push()
            }
          }
        }
      }
  
      stage('Code Quality Analysis with java native tools') {
        parallel {
          stage('PMD') {
            agent {
              docker {
                image 'maven:3.6.0-jdk-8-alpine'
                args '-v /root/.m2/repository:/root/.m2/repository'
                reuseNode true
              }
            }
            steps {
              sh ' mvn pmd:pmd'
            }
          }
          stage('findBugs') {
            agent {
              docker {
                image 'maven:3.6.0-jdk-8-alpine'
                args '-v /root/.m2/repository:/root/.m2/repository'
                reuseNode true
              }
            }
            steps {
              sh ' mvn findbugs:findbugs'
            }
  
          }
  
          stage('JavaDoc') {
            agent {
              docker {
                image 'maven:3.6.0-jdk-8-alpine'
                args '-v /root/.m2/repository:/root/.m2/repository'
                reuseNode true
              }
            }
            steps {
              sh ' mvn javadoc:javadoc'
            }
          }
  
        }
  
        post {
          always {
            recordIssues enabledForFailure: true, tool: spotBugs()
            recordIssues enabledForFailure: true, tool: pmdParser(pattern: '**/target/pmd.xml')
            recordIssues enabledForFailure: true, tools: [javaDoc(), checkStyle(), findBugs()]
            junit skipPublishingChecks: true, testResults: '**/*.xml'
  
          }
        }
      }
  
      stage('Code Quality Analysis with SonarQube') {
        when {
          anyOf {
            branch 'test';
            branch 'develop'
          }
        }
  
        agent {
          docker {
            image 'maven:3.6.0-jdk-8-alpine'
            args "-v /root/.m2/repository:/root/.m2/repository"
            reuseNode true
          }
        }
        steps {
          sh " mvn sonar:sonar -Dsonar.host.url=$SONARQUBE_URL:$SONARQUBE_PORT"
        }
      }
  
      stage('Deploy artifact to Nexus') {
        steps {
          script {
            pom = readMavenPom file: "pom.xml";
            // Find built artifact under target folder
            echo "File src/main/rersources/index.html found!"
            filesByGlob = findFiles(glob: "target/*.${pom.packaging}");
            // Print some info from the artifact found
            echo "${filesByGlob[0].name} ${filesByGlob[0].path} ${filesByGlob[0].directory} ${filesByGlob[0].length} ${filesByGlob[0].lastModified}"
            // Extract the path from the File found
            artifactPath = filesByGlob[0].path;
            echo "File src/main/rersources/index.html found!"
            // Assign to a boolean response verifying If the artifact name exists
            artifactExists = fileExists artifactPath;
            echo "File src/main/rersources/index.html found!"
            echo "test1"
  
            if (artifactExists) {
              echo "test2"
              nexusArtifactUploader(
                nexusVersion: NEXUS_VERSION,
                protocol: NEXUS_PROTOCOL,
                nexusUrl: NEXUS_URL,
                groupId: pom.groupId,
                version: pom.version,
                repository: NEXUS_REPOSITORY,
                credentialsId: NEXUS_CREDENTIAL_ID,
                artifacts: [
                  [artifactId: pom.artifactId,
                    classifier: '',
                    file: artifactPath,
                    type: pom.packaging
                  ],
                  [artifactId: pom.artifactId,
                    classifier: '',
                    file: "pom.xml",
                    type: "pom"
                  ]
                ]
              )
              //sh "echo 'Hello World. Var=$groupId'"
              echo "test3"
            } else {
              error "*** File: ${artifactPath}, could not be found";
            }
          }
        }
      }
      stage('Deploy app to Staging Servers') {
        agent {
          docker {
            image 'rajhisaifeddine/ansible-management'
            reuseNode true
          }
        }
        steps {
          script {
            pom = readMavenPom file: "pom.xml"
            repoPath = "${pom.groupId}".replace(".", "/") + "/${pom.artifactId}"
            version = pom.version
            artifactId = pom.artifactId
            withEnv(["ANSIBLE_HOST_KEY_CHECKING=False", "APP_NAME=${artifactId}", "repoPath=${repoPath}", "version=${version}"]) {
              sh '''
                curl --silent "http://$NEXUS_URL/repository/maven-snapshots/${repoPath}/${version}/maven-metadata.xml" > tmp &&
                egrep '<value>+([0-9\\-\\.]*)' tmp > tmp2 &&
                tail -n 1 tmp2 > tmp3 &&
                tr -d "</value>[:space:]" < tmp3 > tmp4 &&
                REPO_VERSION=$(cat tmp4) &&
                export APP_SRC_URL="http://${NEXUS_URL}/repository/maven-snapshots/${repoPath}/${version}/${APP_NAME}-${REPO_VERSION}.war" &&
                ansible-playbook -v -i ./ansible_provisioning/hosts --extra-vars "host=staging" ./ansible_provisioning/playbook.yml 
 '''
            }
          }
        }
      }
      stage('Deploy to Production Servers') {
  
        tools {
          terraform 'terraform-11'
        }
        stages {
          stage('Setup') {
            steps {
              script {
                currentBuild.displayName = "#" + env.BUILD_NUMBER + " " + params.action + " " + params.cluster
                plan = params.cluster + '.plan'
                println "Getting the kubectl and helm binaries..."
                  (major, minor) = params.k8s_version.split(/\./)
                sh """
                if [!-d "bin"];
                then
                mkdir bin
                (curl -s https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.1.39.zip -o awscliv2.zip 
                unzip awscliv2.zip
                ./aws/install -b ./bin --update
                cd bin
                # 'latest' kubectl is backward compatible with older api versions
                curl --silent -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.21.2/2021-07-05/bin/linux/amd64/kubectl
                curl -fsSL -o - https://get.helm.sh/helm-v3.6.3-linux-amd64.tar.gz | tar -xzf - linux-amd64/helm
                mv linux-amd64/helm .
                rm -rf linux-amd64
                chmod u+x kubectl helm
                ls -l kubectl helm )
                fi
                """
  
              }
            }
          }
  


          stage('Terraform Plan') {
            when {
              expression { params.action == 'create' }
            }
            tools {
              terraform 'terraform-11'
            } 
            steps {
              script {
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', 
                credentialsId: params.credential, 
                accessKeyVariable: 'AWS_ACCESS_KEY_ID',  
                secretKeyVariable: 'AWS_SECRET_ACCESS_KEY']]) {
                  sh """
                    terraform init
                    terraform workspace new ${params.cluster} || true
                    terraform workspace select ${params.cluster}
                    terraform plan \
                      -var cluster-name=${params.cluster} \
                      -var vpc-network=${params.vpc_network} \
                      -var vpc-subnets=${params.num_subnets} \
                      -var inst-type=${params.instance_type} \
                      -var num-workers=${params.num_workers} \
                      -var max-workers=${params.max_workers} \
                      -var cw_logs=${params.cw_logs} \
                      -var inst_key_pair=${params.key_pair} \
                      -var ca=${params.ca} \
                      -var k8s_version=${params.k8s_version} \
                      -var aws_region=${params.region} \
                      -out ${plan}
                  """
                }
              }
            }
          }

          stage('Terraform Apply') {
            when {
              expression {
                params.action == 'create'
              }
            }
            steps {
              script {
                input "Create/update Terraform stack ${params.cluster} in aws?"
                withCredentials([
                  [$class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: params.credential,
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                  ]
                ]) {
                  sh "terraform apply -input=false -auto-approve ${plan}"
                }
              }
            }
          }
          stage('Cluster setup') {
            when {
              expression {
                params.action == 'create'
              }
            }
            steps {
              script {
                withCredentials([
                  [$class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: params.credential,
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                  ]
                ]) {
                  sh "aws eks update-kubeconfig --name ${params.cluster} --region ${params.region}"
                  // If admin_users specified
                  if (params.admin_users != '') {
                    echo "Adding admin_users to configmap aws-auth."
                    sh "./generate-aws-auth-admins.sh ${params.admin_users} | kubectl apply -f -"
                  }
                  // CW Metrics and Container Insights setup
                  // https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-setup-EKS-quickstart.html
                  if (params.cw_metrics == true) {
                    echo "Setting up Cloudwatch metrics and Container Insights."
                    sh """
                      curl --silent https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/latest/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/quickstart/cwagent-fluentd-quickstart.yaml | \\
                        sed "s/{{cluster_name}}/${params.cluster}/;s/{{region_name}}/${params.region}/" | \\
                        kubectl apply -f -
                    """
                  }
                  // https://docs.aws.amazon.com/eks/latest/userguide/metrics-server.html
                  if (params.metrics_server == true) {
                    echo "Setting up k8s metrics-server."
                    sh "kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml"
                  }
                  // https://docs.aws.amazon.com/eks/latest/userguide/dashboard-tutorial.html
                  if (params.dashboard == true) {
                    echo "Setting up k8s dashboard."
                    sh """
                      kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.5/aio/deploy/recommended.yaml
                      kubectl apply -f eks-admin-service-account.yaml
                    """
                    echo "You need to get the secret token and then use kubectl proxy to get to the dashboard:"
                    echo "kubectl -n kube-system describe secret \$(kubectl -n kube-system get secret | grep eks-admin | awk '{print \$1}')"
                    echo "kubectl proxy"
                    echo "Then visit: http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/#!/login"
                    echo "See docs at https://docs.aws.amazon.com/eks/latest/userguide/dashboard-tutorial.html"
                  }
                  // https://docs.aws.amazon.com/eks/latest/userguide/prometheus.html
                  if (params.prometheus == true) {
                    echo "Setting up k8s prometheus."
                    sh """
                    helm repo add prometheus - community https: //prometheus-community.github.io/helm-charts
                    helm repo update
                    helm install prometheus prometheus - community / prometheus\
                      --namespace prometheus\
                      --create - namespace\
                      --set alertmanager.persistentVolume.storageClass = "gp2", server.persistentVolume.storageClass = "gp2"
                    """
                    echo "To connect to prometheus, follow the instructions above, then connect to http://localhost:9090"
                    echo "See docs at https://docs.aws.amazon.com/eks/latest/userguide/prometheus.html"
                    echo "Alternativly use k8s Lens which is much easier (choose Helm for the Prometheus setup its not auto detected)."
                  }
                  if (params.ca == true) {
                    echo "Setting up k8s Cluster Autoscaler."
                    gregion='us'
                    if (params.region =~ '^eu') {
                      gregion='eu'
                    }
                    // CA image tag, which is k8s major version plus CA minor version.
                    switch (params.k8s_version) {
                    case '1.23':
                      tag = '0'
                      break;
                    case '1.22':
                      tag = '0'
                      break;
                    case '1.21':
                      tag = '1'
                      break;
                    }
                    // Setup documented here: https://docs.aws.amazon.com/eks/latest/userguide/cluster-autoscaler.html
                    sh """
                    kubectl apply -f https://raw.githubusercontent.com/kubernetes/autoscaler/master/cluster-autoscaler/cloudprovider/aws/examples/cluster-autoscaler-autodiscover.yaml
                    kubectl -n kube-system annotate deployment.apps/cluster-autoscaler cluster-autoscaler.kubernetes.io/safe-to-evict="false"
                    sleep 5
                    kubectl -n kube-system get deployment.apps/cluster-autoscaler -o json | \\
                      jq | \\
                      sed 's/<YOUR CLUSTER NAME>/${params.cluster}/g' | \\
                      jq '.spec.template.spec.containers[0].command += ["--balance-similar-node-groups","--skip-nodes-with-system-pods=false"]' | \\
                      kubectl apply -f -
                    kubectl -n kube-system set image deployment.apps/cluster-autoscaler cluster-autoscaler=${gregion}.gcr.io/k8s-artifacts-prod/autoscaling/cluster-autoscaler:v${params.k8s_version}.${tag}
                    """
                  }
                  // Also https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-helm/
                  if (params.nginx_ingress == true) {
                    echo "Setting up nginx ingress and load balancer."
                    sh """
                    helm repo add nginx - stable https: //helm.nginx.com/stable
                    helm repo update
                    helm install nginx - ingress nginx - stable / nginx - ingress--namespace nginx - ingress--create - namespace
                    kubectl apply -f nginx-ingress-proxy.yaml
                    echo "Dns name of nginx ingress load balancer is below:"
                    kubectl get svc --namespace=nginx-ingress """
                  }
                  // Updated cert-manager version installed late 2021
                  if (params.cert_manager == true) {
                    echo "Setting up cert-manager."
                    sh """
                      helm repo add jetstack https://charts.jetstack.io || true
                      helm repo update
                      helm install cert-manager jetstack/cert-manager --namespace cert-manager --version v1.5.3 --set installCRDs=true --create-namespace
                      sleep 30 # allow cert-manager setup in the cluster
                      kubectl apply -f cluster-issuer-le-staging.yaml
                      kubectl apply -f cluster-issuer-le-prod.yaml
                      """
                  }
  
                }
  
              }
            }
          }
  
          stage('deploy application in production cluster') {
            when {
              expression {
                params.action == 'create'
              }
            }
            steps {
              script {
                withCredentials([
                  [$class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: params.credential,
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                  ]
                ]) {
                  sh """
                    aws eks update-kubeconfig --name ${params.cluster} --region ${params.region}
                    kubectl apply - f app - demo.yaml """
                }
              }
            }
          }
  
          stage('Terraform Destroy') {
            when {
              expression {
                params.action == 'destroy'
              }
            }
            steps {
              script {
                input "Destroy Terraform stack ${params.cluster} in aws?"
                withCredentials([
                  [$class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: params.credential,
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                  ]
                ]) {
                  sh """
                    aws eks update-kubeconfig --name ${params.cluster} --region ${params.region}
                    helm uninstall prometheus --namespace prometheus || true
                    helm uninstall cert-manager --namespace cert-manager || true
                    kubectl delete -f nginx-ingress-proxy.yaml || true
                    helm uninstall nginx-ingress --namespace nginx-ingress || true
                    sleep 20
                    terraform workspace select ${params.cluster}
                    terraform destroy -auto-approve                  
                  """
                }
              }
            }
          }
        }
      }
    }
  }
