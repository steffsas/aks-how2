# Important Considerations

This folder contains a sample CI pipeline description for Azure DevOps. This means that this CI pipeline can be used to build increments for applications that can be subsequently deployed from a CD pipeline. You can use it as a starting point for your own CI pipeline.

However, each CI pipeline must take into account any special properties of an application, so that requirements can also be reflected in the CI pipeline. The CI pipeline also requires that a working Dockerfile exists in the root directory of the application.

# Structure

The CI Pipeline is structured as follows:

* Two CI pipelines are defined for each application, one for the productive application (``pipeline-prod-temp.yaml``, main branch) and one for the test application (``pipeline-dev-temp.yaml``, test branch). However, both pipelines use the same template (``pipeline-template.yaml``) and control it via parameters (production=true/false). This has the advantage that a complete overview of productive/test environment is reflected in only one description of the pipeline.
* The pipelines are controlled by variables (``variables.yaml``). Here basic assumptions about the application are given. For example, the name of the application is defined here (``applicationName``). The values in the section specific should be adapted accordingly to your application's need. The values in the section generic should only be adapted, if something in the cluster changes (e.g. the clusterissuer) or your application is structured differently to all other applications.

