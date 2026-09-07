from django.apps import AppConfig


class AssessmentsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.assessments"

    def ready(self):
        # Register the protected file policy callback for assessment result files
        from apps.security.file_policies import register_file_policy
        from apps.assessments.policies import assessment_result_file_policy

        register_file_policy("assessment_result_file", assessment_result_file_policy)
