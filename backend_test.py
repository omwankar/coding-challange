#!/usr/bin/env python3
"""
Comprehensive Backend API Testing for Store Rating System
Tests all endpoints with proper authentication and role-based access
"""

import requests
import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional

class StoreRatingAPITester:
    def __init__(self, base_url="https://storerate.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tokens = {}  # Store tokens for different user types
        self.users = {}   # Store user data
        self.stores = {}  # Store store data
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name: str, success: bool, details: str = ""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            status = "✅ PASS"
        else:
            status = "❌ FAIL"
        
        result = {
            "test_name": name,
            "status": "PASS" if success else "FAIL",
            "details": details,
            "timestamp": datetime.now().isoformat()
        }
        self.test_results.append(result)
        print(f"{status} - {name}: {details}")

    def make_request(self, method: str, endpoint: str, data: Dict = None, 
                    token: str = None, expected_status: int = 200) -> tuple:
        """Make HTTP request with proper error handling"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        if token:
            headers['Authorization'] = f'Bearer {token}'

        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=30)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")

            success = response.status_code == expected_status
            response_data = {}
            
            try:
                response_data = response.json()
            except:
                response_data = {"raw_response": response.text}

            return success, response.status_code, response_data

        except requests.exceptions.RequestException as e:
            return False, 0, {"error": str(e)}

    def test_admin_login(self):
        """Test admin login with pre-seeded credentials"""
        success, status, data = self.make_request(
            'POST', 'auth/login',
            data={
                "email": "admin@storerate.com",
                "password": "AdminPass123!"
            }
        )
        
        if success and 'access_token' in data:
            self.tokens['admin'] = data['access_token']
            self.users['admin'] = data['user']
            self.log_test("Admin Login", True, f"Admin logged in successfully, role: {data['user']['role']}")
            return True
        else:
            self.log_test("Admin Login", False, f"Status: {status}, Response: {data}")
            return False

    def test_normal_user_registration(self):
        """Test normal user registration"""
        timestamp = datetime.now().strftime('%H%M%S')
        user_data = {
            "name": f"Test Normal User Account {timestamp}",
            "email": f"testuser{timestamp}@example.com",
            "address": f"123 Test Street, Test City, Test State {timestamp}",
            "password": "TestPass123!"
        }
        
        success, status, data = self.make_request(
            'POST', 'auth/register',
            data=user_data
        )
        
        if success and 'access_token' in data:
            self.tokens['normal_user'] = data['access_token']
            self.users['normal_user'] = data['user']
            self.log_test("Normal User Registration", True, f"User registered: {data['user']['email']}")
            return True
        else:
            self.log_test("Normal User Registration", False, f"Status: {status}, Response: {data}")
            return False

    def test_store_owner_registration(self):
        """Test store owner registration"""
        timestamp = datetime.now().strftime('%H%M%S')
        registration_data = {
            "user": {
                "name": f"Test Store Owner Account {timestamp}",
                "email": f"storeowner{timestamp}@example.com",
                "address": f"456 Store Owner Street, Business City {timestamp}",
                "password": "StorePass123!"
            },
            "store": {
                "name": f"Test Store {timestamp}",
                "email": f"store{timestamp}@example.com",
                "address": f"789 Store Address, Commercial District {timestamp}"
            }
        }
        
        success, status, data = self.make_request(
            'POST', 'auth/store-owner-register',
            data=registration_data,
            expected_status=200
        )
        
        if success and 'user_id' in data and 'store_id' in data:
            self.stores['pending_store_id'] = data['store_id']
            self.users['store_owner_data'] = registration_data
            self.log_test("Store Owner Registration", True, f"Store owner registered, store ID: {data['store_id']}")
            return True
        else:
            self.log_test("Store Owner Registration", False, f"Status: {status}, Response: {data}")
            return False

    def test_admin_dashboard_stats(self):
        """Test admin dashboard statistics"""
        if 'admin' not in self.tokens:
            self.log_test("Admin Dashboard Stats", False, "Admin token not available")
            return False
            
        success, status, data = self.make_request(
            'GET', 'admin/dashboard',
            token=self.tokens['admin']
        )
        
        if success and 'total_users' in data:
            self.log_test("Admin Dashboard Stats", True, 
                         f"Users: {data['total_users']}, Stores: {data['total_stores']}, Ratings: {data['total_ratings']}")
            return True
        else:
            self.log_test("Admin Dashboard Stats", False, f"Status: {status}, Response: {data}")
            return False

    def test_admin_get_users(self):
        """Test admin get all users"""
        if 'admin' not in self.tokens:
            self.log_test("Admin Get Users", False, "Admin token not available")
            return False
            
        success, status, data = self.make_request(
            'GET', 'admin/users',
            token=self.tokens['admin']
        )
        
        if success and isinstance(data, list):
            self.log_test("Admin Get Users", True, f"Retrieved {len(data)} users")
            return True
        else:
            self.log_test("Admin Get Users", False, f"Status: {status}, Response: {data}")
            return False

    def test_admin_get_stores(self):
        """Test admin get all stores"""
        if 'admin' not in self.tokens:
            self.log_test("Admin Get Stores", False, "Admin token not available")
            return False
            
        success, status, data = self.make_request(
            'GET', 'admin/stores',
            token=self.tokens['admin']
        )
        
        if success and isinstance(data, list):
            self.log_test("Admin Get Stores", True, f"Retrieved {len(data)} stores")
            # Find our test store for approval testing
            for store in data:
                if store.get('status') == 'pending' and 'Test Store' in store.get('name', ''):
                    self.stores['test_store'] = store
                    break
            return True
        else:
            self.log_test("Admin Get Stores", False, f"Status: {status}, Response: {data}")
            return False

    def test_admin_approve_store(self):
        """Test admin store approval"""
        if 'admin' not in self.tokens:
            self.log_test("Admin Approve Store", False, "Admin token not available")
            return False
            
        if 'test_store' not in self.stores:
            self.log_test("Admin Approve Store", False, "No test store found for approval")
            return False
            
        store_id = self.stores['test_store']['id']
        success, status, data = self.make_request(
            'PUT', f'admin/stores/{store_id}/approve',
            token=self.tokens['admin']
        )
        
        if success:
            self.log_test("Admin Approve Store", True, f"Store {store_id} approved successfully")
            return True
        else:
            self.log_test("Admin Approve Store", False, f"Status: {status}, Response: {data}")
            return False

    def test_store_owner_login(self):
        """Test store owner login after registration"""
        if 'store_owner_data' not in self.users:
            self.log_test("Store Owner Login", False, "Store owner data not available")
            return False
            
        user_data = self.users['store_owner_data']['user']
        success, status, data = self.make_request(
            'POST', 'auth/login',
            data={
                "email": user_data['email'],
                "password": user_data['password']
            }
        )
        
        if success and 'access_token' in data:
            self.tokens['store_owner'] = data['access_token']
            self.users['store_owner'] = data['user']
            self.log_test("Store Owner Login", True, f"Store owner logged in: {data['user']['email']}")
            return True
        else:
            self.log_test("Store Owner Login", False, f"Status: {status}, Response: {data}")
            return False

    def test_get_approved_stores(self):
        """Test getting approved stores (normal user access)"""
        if 'normal_user' not in self.tokens:
            self.log_test("Get Approved Stores", False, "Normal user token not available")
            return False
            
        success, status, data = self.make_request(
            'GET', 'stores',
            token=self.tokens['normal_user']
        )
        
        if success and isinstance(data, list):
            approved_stores = [s for s in data if s.get('status') == 'approved']
            self.stores['approved_stores'] = approved_stores
            self.log_test("Get Approved Stores", True, f"Retrieved {len(approved_stores)} approved stores")
            return True
        else:
            self.log_test("Get Approved Stores", False, f"Status: {status}, Response: {data}")
            return False

    def test_submit_rating(self):
        """Test rating submission"""
        if 'normal_user' not in self.tokens:
            self.log_test("Submit Rating", False, "Normal user token not available")
            return False
            
        if 'approved_stores' not in self.stores or not self.stores['approved_stores']:
            self.log_test("Submit Rating", False, "No approved stores available for rating")
            return False
            
        store = self.stores['approved_stores'][0]
        rating_data = {
            "store_id": store['id'],
            "rating": 4
        }
        
        success, status, data = self.make_request(
            'POST', 'ratings',
            data=rating_data,
            token=self.tokens['normal_user']
        )
        
        if success:
            self.log_test("Submit Rating", True, f"Rating submitted for store {store['name']}")
            return True
        else:
            self.log_test("Submit Rating", False, f"Status: {status}, Response: {data}")
            return False

    def test_update_rating(self):
        """Test rating update (same user, same store)"""
        if 'normal_user' not in self.tokens:
            self.log_test("Update Rating", False, "Normal user token not available")
            return False
            
        if 'approved_stores' not in self.stores or not self.stores['approved_stores']:
            self.log_test("Update Rating", False, "No approved stores available for rating update")
            return False
            
        store = self.stores['approved_stores'][0]
        rating_data = {
            "store_id": store['id'],
            "rating": 5  # Update to 5 stars
        }
        
        success, status, data = self.make_request(
            'POST', 'ratings',
            data=rating_data,
            token=self.tokens['normal_user']
        )
        
        if success:
            self.log_test("Update Rating", True, f"Rating updated to 5 stars for store {store['name']}")
            return True
        else:
            self.log_test("Update Rating", False, f"Status: {status}, Response: {data}")
            return False

    def test_get_my_rating(self):
        """Test getting user's own rating for a store"""
        if 'normal_user' not in self.tokens:
            self.log_test("Get My Rating", False, "Normal user token not available")
            return False
            
        if 'approved_stores' not in self.stores or not self.stores['approved_stores']:
            self.log_test("Get My Rating", False, "No approved stores available")
            return False
            
        store = self.stores['approved_stores'][0]
        success, status, data = self.make_request(
            'GET', f'ratings/my-rating/{store["id"]}',
            token=self.tokens['normal_user']
        )
        
        if success and 'rating' in data:
            self.log_test("Get My Rating", True, f"Retrieved rating: {data['rating']} for store {store['name']}")
            return True
        else:
            self.log_test("Get My Rating", False, f"Status: {status}, Response: {data}")
            return False

    def test_password_validation(self):
        """Test password validation rules"""
        test_cases = [
            ("short", "Short1!", False, "Password too short"),
            ("toolongpassword123!", "toolongpassword123!", False, "Password too long"),
            ("nouppercase1!", "nouppercase1!", False, "No uppercase letter"),
            ("NOLOWERCASE1!", "NOLOWERCASE1!", False, "No lowercase letter"),
            ("NoSpecialChar1", "NoSpecialChar1", False, "No special character"),
            ("ValidPass1!", "ValidPass1!", True, "Valid password")
        ]
        
        passed = 0
        for name, password, should_pass, description in test_cases:
            timestamp = datetime.now().strftime('%H%M%S%f')
            user_data = {
                "name": f"Password Test User {timestamp}",
                "email": f"pwtest{timestamp}@example.com",
                "address": f"Password Test Address {timestamp}",
                "password": password
            }
            
            success, status, data = self.make_request(
                'POST', 'auth/register',
                data=user_data,
                expected_status=200 if should_pass else 400
            )
            
            if (success and should_pass) or (not success and not should_pass):
                passed += 1
                self.log_test(f"Password Validation - {description}", True, f"Correctly handled: {password}")
            else:
                self.log_test(f"Password Validation - {description}", False, 
                             f"Expected {'success' if should_pass else 'failure'}, got status {status}")
        
        return passed == len(test_cases)

    def test_role_based_access(self):
        """Test role-based access control"""
        # Test normal user trying to access admin endpoints
        if 'normal_user' not in self.tokens:
            self.log_test("Role-Based Access Control", False, "Normal user token not available")
            return False
            
        success, status, data = self.make_request(
            'GET', 'admin/dashboard',
            token=self.tokens['normal_user'],
            expected_status=403
        )
        
        if not success and status == 403:
            self.log_test("Role-Based Access Control", True, "Normal user correctly denied admin access")
            return True
        else:
            self.log_test("Role-Based Access Control", False, f"Expected 403, got {status}")
            return False

    def run_all_tests(self):
        """Run all tests in sequence"""
        print("🚀 Starting Store Rating System API Tests")
        print("=" * 60)
        
        # Authentication Tests
        print("\n📝 Authentication Tests")
        self.test_admin_login()
        self.test_normal_user_registration()
        self.test_store_owner_registration()
        self.test_store_owner_login()
        
        # Admin Functionality Tests
        print("\n👑 Admin Functionality Tests")
        self.test_admin_dashboard_stats()
        self.test_admin_get_users()
        self.test_admin_get_stores()
        self.test_admin_approve_store()
        
        # Store and Rating Tests
        print("\n🏪 Store and Rating Tests")
        self.test_get_approved_stores()
        self.test_submit_rating()
        self.test_update_rating()
        self.test_get_my_rating()
        
        # Validation and Security Tests
        print("\n🔒 Validation and Security Tests")
        self.test_password_validation()
        self.test_role_based_access()
        
        # Print Results
        print("\n" + "=" * 60)
        print(f"📊 Test Results: {self.tests_passed}/{self.tests_run} tests passed")
        print(f"✅ Success Rate: {(self.tests_passed/self.tests_run)*100:.1f}%")
        
        if self.tests_passed < self.tests_run:
            print("\n❌ Failed Tests:")
            for result in self.test_results:
                if result['status'] == 'FAIL':
                    print(f"  - {result['test_name']}: {result['details']}")
        
        return self.tests_passed == self.tests_run

def main():
    """Main test execution"""
    tester = StoreRatingAPITester()
    
    try:
        success = tester.run_all_tests()
        
        # Save detailed results
        with open('/app/test_reports/backend_api_test_results.json', 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'total_tests': tester.tests_run,
                'passed_tests': tester.tests_passed,
                'success_rate': (tester.tests_passed/tester.tests_run)*100 if tester.tests_run > 0 else 0,
                'test_results': tester.test_results
            }, f, indent=2)
        
        return 0 if success else 1
        
    except Exception as e:
        print(f"❌ Test execution failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())