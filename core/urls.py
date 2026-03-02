from django.urls import path

from . import views

urlpatterns = [
    path("register/", views.register_user),
    path("request-otp/", views.request_otp),
    path("verify-otp/", views.verify_otp),  # 👈 add this line
    path("logout/", views.logout),
    path("current-user/", views.account),
    path("project_story/",views.project_story),
    path("me/",views.me_view),
    path("account/", views.account),
    path("my-workspaces/", views.my_workspaces),

    
    path("workspaces/", views.workspaces),  # GET list / POST create workspace
    path("workspaces_info/", views.workspace_info),  # GET list / POST create workspace
   path("workspaces/<int:workspace_id>/assign-leader/",views.assign_workspace_leader),
    path("workspaces/<int:workspace_id>/members/",views.workspace_members_view),
    path("workspaces/<int:workspace_id>/channels/",views.channels_view),

    # Channel members
    path("channels/<int:channel_id>/members/",views.channel_members_view),
    path("messages/", views.messages),  # GET list / POST create channel
    path("activities/", views.activities),
    path("notifications/", views.notifications),

    path("metrics/messages-per-day", views.metrics_messages_per_day),
    path("metrics/active-users", views.metrics_active_users),
    path("refresh/", views.refresh_endpoint),
    
    path("tasks/", views.tasks),  # GET workspace tasks
    path("tasks/create/", views.task_create),  # POST create
    path("tasks/update/", views.task_update),  # POST update
    path("tasks/delete/", views.task_delete),  # optional
    
    
    # admin:
    path("admin/users/update/", views.super_admin_update_admin),
    path("admin/createworkspace/", views.admin_create_workspace),
    path("manageworkspaces/", views.manage_workspace_member),
    
    
    # GitHub integration management (auth required)
    # path("github/integrations/", views.github_integrations),
    # GitHub webhook (public)
    path("github/webhook/", views.github_webhook),

    path("dm/send/", views.dm_send_message),
    path("dm/messages/", views.dm_list_messages),
    path("dm/edit/", views.dm_edit_message),
    path("dm/delete/", views.dm_delete_message),
    
    
 # ==============================
# ADMIN PLATFORM
# ==============================
    path("stats/", views.admin_stats),
    path("admin/workspaces/<int:workspace_id>/overview/", views.admin_workspace_overview),
    path("workspaces/<int:workspace_id>/channels/", views.admin_workspace_channels),
    path("users/<int:user_id>/workspaces/", views.admin_user_workspaces),

    # ==============================
    # WORKSPACE ANALYTICS
    # ==============================
    path("workspaces/<int:workspace_id>/overview/", views.workspace_overview),
    path("admin/users/", views.admin_list_users),
    path("admin/users/set-role/", views.admin_set_user_role),
    path("fetch_repo_history", views.fetch_all_history_view),
    path("connect_repository", views.connect_repository),
]
