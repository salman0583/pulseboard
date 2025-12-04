from django.urls import path

from . import views

urlpatterns = [
    path("register/", views.register_user),
    path("request-otp/", views.request_otp),
    path("verify-otp/", views.verify_otp),  # 👈 add this line
    path("logout/", views.logout),
    path("current-user/", views.account),

    
    path("workspaces/", views.workspaces),  # GET list / POST create workspace
    path("workspaces/", views.workspace_info),  # GET list / POST create workspace
    path("workspace-members/", views.workspace_members),
    path("workspace-updates/", views.workspace_updates_view),

    path("channels/", views.channels),  # GET list / POST create channel
    path("messages/", views.messages),  # GET list / POST create channel
    path("activities/", views.activities),
    
    path("metrics/messages-per-day", views.metrics_messages_per_day),
    path("metrics/active-users", views.metrics_active_users),
    path("refresh/", views.refresh_endpoint),
    
    path("tasks/", views.tasks),  # GET workspace tasks
    path("tasks/create/", views.task_create),  # POST create
    path("tasks/update/", views.task_update),  # POST update
    path("tasks/delete/", views.task_delete),  # optional
    
    
    # admin:
    path("admin/users/", views.admin_users),
    path("admin/users/update-role/", views.admin_update_user_roles),
    path("admin/workspaces/", views.admin_workspaces),
    
    
    # GitHub integration management (auth required)
    path("github/integrations/", views.github_integrations),
    # GitHub webhook (public)
    path("github/webhook/", views.github_webhook),

    
]
