'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000';

interface User {
  id: number;
  email: string;
  role: string;
  role_display: string;
  is_active: boolean;
}

interface CurrentUser {
  id: number;
  email: string;
  is_admin: boolean;
}

const ROLE_OPTIONS = [
  { value: 'viewer', label: 'Viewer' },
  { value: 'content_manager', label: 'Content Manager' },
  { value: 'legal_reviewer', label: 'Legal Reviewer' },
  { value: 'admin', label: 'Admin' },
];

export default function TeamPage() {
  const router = useRouter();
  const [users, setUsers] = useState<User[]>([]);
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteLoading, setInviteLoading] = useState(false);
  const [inviteError, setInviteError] = useState('');
  const [inviteSuccess, setInviteSuccess] = useState('');
  const [roleUpdateLoading, setRoleUpdateLoading] = useState<number | null>(null);
  const [roleError, setRoleError] = useState<string | null>(null);
  const [roleSuccess, setRoleSuccess] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<number | null>(null);
  const [showConfirmDialog, setShowConfirmDialog] = useState<{
    userId: number;
    action: 'deactivate' | 'reactivate';
    email: string;
  } | null>(null);

  useEffect(() => {
    fetchCurrentUser();
  }, []);

  useEffect(() => {
    if (currentUser) {
      if (!currentUser.is_admin) {
        router.push('/dashboard');
      } else {
        fetchUsers();
      }
    }
  }, [currentUser, router]);

  const fetchCurrentUser = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/v1/auth/me/`, {
        withCredentials: true,
      });
      setCurrentUser(response.data);
    } catch (error) {
      console.error('Error fetching current user:', error);
      router.push('/login');
    }
  };

  const fetchUsers = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/v1/auth/users/`, {
        withCredentials: true,
      });
      setUsers(response.data.users);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching users:', error);
      setLoading(false);
    }
  };

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setInviteError('');
    setInviteSuccess('');
    setInviteLoading(true);

    try {
      const response = await axios.post(
        `${API_BASE_URL}/api/v1/auth/invitations/send/`,
        { email: inviteEmail },
        { withCredentials: true }
      );

      setInviteSuccess(response.data.message);
      setInviteEmail('');
      setInviteLoading(false);
    } catch (error: any) {
      if (error.response?.data?.email) {
        setInviteError(error.response.data.email[0]);
      } else if (error.response?.data?.error) {
        setInviteError(error.response.data.error);
      } else {
        setInviteError('Failed to send invitation. Please try again.');
      }
      setInviteLoading(false);
    }
  };

  const handleRoleChange = async (userId: number, newRole: string, oldRole: string) => {
    if (oldRole === newRole) {
      return; // No change
    }

    setRoleError(null);
    setRoleSuccess(null);
    setRoleUpdateLoading(userId);

    try {
      const response = await axios.post(
        `${API_BASE_URL}/api/v1/auth/users/${userId}/assign-role/`,
        { role: newRole },
        { withCredentials: true }
      );

      setRoleSuccess(response.data.message);
      setRoleUpdateLoading(null);

      // Refresh users list
      fetchUsers();

      // Clear success message after 3 seconds
      setTimeout(() => setRoleSuccess(null), 3000);
    } catch (error: any) {
      if (error.response?.data?.error) {
        setRoleError(error.response.data.error);
      } else {
        setRoleError('Failed to update role. Please try again.');
      }
      setRoleUpdateLoading(null);

      // Refresh users list to revert UI
      fetchUsers();
    }
  };

  const handleDeactivate = (userId: number, email: string) => {
    setShowConfirmDialog({ userId, action: 'deactivate', email });
  };

  const handleReactivate = (userId: number, email: string) => {
    setShowConfirmDialog({ userId, action: 'reactivate', email });
  };

  const confirmAction = async () => {
    if (!showConfirmDialog) return;

    const { userId, action } = showConfirmDialog;

    setRoleError(null);
    setRoleSuccess(null);
    setActionLoading(userId);
    setShowConfirmDialog(null);

    try {
      const endpoint = action === 'deactivate' ? 'deactivate' : 'reactivate';
      const response = await axios.post(
        `${API_BASE_URL}/api/v1/auth/users/${userId}/${endpoint}/`,
        {},
        { withCredentials: true }
      );

      setRoleSuccess(response.data.message);
      setActionLoading(null);

      // Refresh users list
      fetchUsers();

      // Clear success message after 3 seconds
      setTimeout(() => setRoleSuccess(null), 3000);
    } catch (error: any) {
      if (error.response?.data?.error) {
        setRoleError(error.response.data.error);
      } else {
        setRoleError(`Failed to ${action} account. Please try again.`);
      }
      setActionLoading(null);
    }
  };

  const cancelAction = () => {
    setShowConfirmDialog(null);
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-gray-600">Loading...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Team Management</h1>
          <p className="mt-2 text-gray-600">
            Invite team members and manage roles
          </p>
        </div>

        {/* Invite Team Member Section */}
        <div className="bg-white shadow rounded-lg p-6 mb-8">
          <h2 className="text-xl font-semibold text-gray-900 mb-4">
            Invite Team Member
          </h2>
          <form onSubmit={handleInvite} className="space-y-4">
            <div>
              <label
                htmlFor="email"
                className="block text-sm font-medium text-gray-700"
              >
                Email Address
              </label>
              <input
                type="email"
                id="email"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                required
                className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                placeholder="colleague@example.com"
              />
            </div>

            {inviteError && (
              <div className="text-red-600 text-sm">{inviteError}</div>
            )}

            {inviteSuccess && (
              <div className="text-green-600 text-sm">{inviteSuccess}</div>
            )}

            <button
              type="submit"
              disabled={inviteLoading}
              className="w-full sm:w-auto px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {inviteLoading ? 'Sending...' : 'Send Invitation'}
            </button>
          </form>
        </div>

        {/* Team Members List */}
        <div className="bg-white shadow rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-xl font-semibold text-gray-900">
              Team Members
            </h2>
          </div>

          {roleError && (
            <div className="px-6 py-3 bg-red-50 text-red-600 text-sm">
              {roleError}
            </div>
          )}

          {roleSuccess && (
            <div className="px-6 py-3 bg-green-50 text-green-600 text-sm">
              {roleSuccess}
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th
                    scope="col"
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                  >
                    Email
                  </th>
                  <th
                    scope="col"
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                  >
                    Role
                  </th>
                  <th
                    scope="col"
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                  >
                    Status
                  </th>
                  <th
                    scope="col"
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                  >
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {users.map((user) => {
                  const isCurrentUser = currentUser?.id === user.id;
                  const isUpdating = roleUpdateLoading === user.id;

                  return (
                    <tr key={user.id}>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {user.email}
                        {isCurrentUser && (
                          <span className="ml-2 text-xs text-gray-500">
                            (You)
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <select
                          value={user.role}
                          onChange={(e) =>
                            handleRoleChange(user.id, e.target.value, user.role)
                          }
                          disabled={isCurrentUser || isUpdating}
                          className="block w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
                        >
                          {ROLE_OPTIONS.map((option) => (
                            <option key={option.value} value={option.value}>
                              {option.label}
                            </option>
                          ))}
                        </select>
                        {isCurrentUser && (
                          <p className="mt-1 text-xs text-gray-500">
                            Cannot change your own role
                          </p>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {user.is_active ? (
                          <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                            Active
                          </span>
                        ) : (
                          <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">
                            Inactive
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm">
                        {user.is_active ? (
                          <button
                            onClick={() => handleDeactivate(user.id, user.email)}
                            disabled={isCurrentUser || actionLoading === user.id}
                            className="text-red-600 hover:text-red-900 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {actionLoading === user.id ? 'Processing...' : 'Deactivate'}
                          </button>
                        ) : (
                          <button
                            onClick={() => handleReactivate(user.id, user.email)}
                            disabled={actionLoading === user.id}
                            className="text-green-600 hover:text-green-900 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {actionLoading === user.id ? 'Processing...' : 'Reactivate'}
                          </button>
                        )}
                        {isCurrentUser && user.is_active && (
                          <p className="mt-1 text-xs text-gray-500">
                            Cannot deactivate your own account
                          </p>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {users.length === 0 && (
            <div className="px-6 py-12 text-center text-gray-500">
              No team members found
            </div>
          )}
        </div>

        {/* Confirmation Dialog */}
        {showConfirmDialog && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Confirm {showConfirmDialog.action === 'deactivate' ? 'Deactivation' : 'Reactivation'}
              </h3>
              <p className="text-gray-600 mb-6">
                Are you sure you want to {showConfirmDialog.action} the account for{' '}
                <span className="font-semibold">{showConfirmDialog.email}</span>?
              </p>
              <div className="flex space-x-4">
                <button
                  onClick={confirmAction}
                  className="flex-1 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500"
                >
                  {showConfirmDialog.action === 'deactivate' ? 'Deactivate' : 'Reactivate'}
                </button>
                <button
                  onClick={cancelAction}
                  className="flex-1 px-4 py-2 bg-gray-200 text-gray-800 rounded-md hover:bg-gray-300 focus:outline-none focus:ring-2 focus:ring-gray-500"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
