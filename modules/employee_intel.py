"""Employee Intelligence Module - Company employee discovery and leaked credential checking"""

import requests
import re
from typing import Dict, List, Optional
from urllib.parse import quote
import hashlib


class EmployeeIntel:
    """Employee and company intelligence gathering"""
    
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Have I Been Pwned API
        self.hibp_api = "https://api.pwnedpasswords.com"
        self.hibp_email_api = "https://haveibeenpwned.com/api/v3"
        
        # Common email patterns for employees
        self.email_patterns = [
            'firstname.lastname',
            'firstnamelastname',
            'f.lastname',
            'firstname.l',
            'flastname',
            'firstname_lastname',
            'f_lastname'
        ]
    
    def discover_employees(self, company: str, method: str = "linkedin") -> List[Dict]:
        """Discover employees of a company"""
        employees = []
        
        if method == "linkedin":
            employees = self._discover_from_linkedin(company)
        elif method == "github":
            employees = self._discover_from_github(company)
        elif method == "gitlab":
            employees = self._discover_from_gitlab(company)
        elif method == "website":
            employees = self._discover_from_website(company)
        
        return employees
    
    def _discover_from_linkedin(self, company: str) -> List[Dict]:
        """
        LinkedIn people search requires auth — return public pivot URLs only.
        Real employee names come from GitHub/GitLab/website methods.
        """
        q = quote(company)
        return [{
            "name": None,
            "title": None,
            "company": company,
            "linkedin_url": None,
            "email": None,
            "social_profiles": {},
            "pivots": {
                "company_search": f"https://www.linkedin.com/search/results/companies/?keywords={q}",
                "people_search": f"https://www.linkedin.com/search/results/people/?keywords={q}",
                "google_dork": f"https://www.google.com/search?q=site%3Alinkedin.com%2Fin+{q}",
            },
            "note": "LinkedIn scraping blocked without session; use pivots manually or GH/GL discovery",
        }]
    
    def _discover_from_github(self, company: str) -> List[Dict]:
        """Discover employees from GitHub"""
        employees = []
        
        try:
            # Search GitHub for users with company in bio or email
            url = f"https://api.github.com/search/users?q={quote(company)}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for user in data.get('items', [])[:50]:  # Limit to 50
                    username = user.get('login')
                    profile_url = user.get('html_url')
                    
                    # Get user details
                    try:
                        user_url = f"https://api.github.com/users/{username}"
                        user_response = requests.get(user_url, headers=self.headers, timeout=10)
                        if user_response.status_code == 200:
                            user_data = user_response.json()
                            
                            # Strict company field match (avoid username/search noise)
                            user_company = (user_data.get('company') or '').strip()
                            if self._company_field_match(company, user_company):
                                employees.append({
                                    'name': user_data.get('name', username),
                                    'title': 'Developer',  # GitHub doesn't provide titles
                                    'company': user_data.get('company', company),
                                    'github_url': profile_url,
                                    'email': user_data.get('email'),
                                    'location': user_data.get('location'),
                                    'bio': user_data.get('bio'),
                                    'social_profiles': {
                                        'github': profile_url
                                    },
                                    'confidence': 'high',
                                    'match_reason': 'github_company_field',
                                })
                    except:
                        continue
        except:
            pass
        
        return employees
    
    @staticmethod
    def _company_field_match(target: str, user_company: str) -> bool:
        """Strict match between search target and a profile company field."""
        t = (target or "").strip().lower()
        u = (user_company or "").strip().lower()
        if not t or not u:
            return False
        # strip common @ prefix used on GitHub company fields
        u_clean = u.lstrip("@").strip()
        t_clean = t.lstrip("@").strip()
        if not u_clean:
            return False
        if u_clean == t_clean:
            return True
        # allow "Acme Inc" vs "acme" only if target is long enough
        if len(t_clean) >= 4 and (t_clean in u_clean or u_clean in t_clean):
            # reject tiny token collisions (e.g. "inc", "co")
            if len(t_clean) < 5 and t_clean not in u_clean.split():
                return False
            # require word-ish boundary for short targets
            if len(t_clean) < 6:
                parts = re.split(r"[\s,/@\-]+", u_clean)
                return t_clean in parts or any(p.startswith(t_clean) for p in parts if len(p) >= len(t_clean))
            return True
        return False

    def _discover_from_gitlab(self, company: str) -> List[Dict]:
        """Discover employees from GitLab (org/group members only — not username==company)."""
        employees = []
        slug = re.sub(r"[^a-z0-9\-]", "", (company or "").lower().replace(" ", "-"))
        if not slug:
            return employees
        try:
            # Prefer group lookup over username match (old code falsely treated
            # "user named Acme" as an employee of Acme).
            gurl = f"https://gitlab.com/api/v4/groups/{quote(slug, safe='')}"
            gr = requests.get(gurl, headers=self.headers, timeout=10)
            if gr.status_code != 200:
                return employees
            members_url = f"https://gitlab.com/api/v4/groups/{quote(slug, safe='')}/members"
            response = requests.get(members_url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                users = response.json() if isinstance(response.json(), list) else []
                for user in users[:50]:
                    employees.append({
                        'name': user.get('name', user.get('username')),
                        'title': 'Developer',
                        'company': company,
                        'gitlab_url': user.get('web_url'),
                        'email': user.get('email'),
                        'social_profiles': {
                            'gitlab': user.get('web_url')
                        },
                        'confidence': 'high',
                        'match_reason': 'gitlab_group_member',
                    })
        except Exception:
            pass
        return employees
    
    def _discover_from_website(self, company: str) -> List[Dict]:
        """Discover employees from company website"""
        employees = []
        
        # Try common employee page patterns
        common_paths = [
            '/team',
            '/about',
            '/about-us',
            '/people',
            '/employees',
            '/staff',
            '/leadership'
        ]
        
        for path in common_paths:
            try:
                url = f"https://{company}{path}"
                response = requests.get(url, headers=self.headers, timeout=10)
                if response.status_code == 200:
                    # Extract names and emails from page
                    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
                    for email in emails:
                        if company.lower() in email.lower():
                            employees.append({
                                'name': email.split('@')[0].replace('.', ' ').title(),
                                'title': 'Employee',
                                'company': company,
                                'email': email,
                                'source': url
                            })
            except:
                continue
        
        return employees
    
    def find_personal_emails(self, employee: Dict) -> List[str]:
        """Find personal email addresses for an employee"""
        emails = []
        
        name = employee.get('name', '')
        if not name:
            return emails
        
        # Parse name
        name_parts = name.lower().split()
        if len(name_parts) >= 2:
            firstname = name_parts[0]
            lastname = name_parts[-1]
            
            # Common email domains
            domains = [
                'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                'protonmail.com', 'icloud.com', 'aol.com', 'mail.com'
            ]
            
            # Generate email variations
            patterns = [
                f"{firstname}.{lastname}",
                f"{firstname}{lastname}",
                f"{firstname[0]}.{lastname}",
                f"{firstname}.{lastname[0]}",
                f"{firstname[0]}{lastname}",
                f"{firstname}_{lastname}",
                f"{firstname}-{lastname}"
            ]
            
            for pattern in patterns:
                for domain in domains:
                    emails.append(f"{pattern}@{domain}")
        
        return list(set(emails))
    
    def check_leaked_credentials(self, email: str, api_key: Optional[str] = None) -> Dict:
        """Check if email has leaked credentials using Have I Been Pwned"""
        result = {
            'email': email,
            'breached': False,
            'breaches': [],
            'pastes': []
        }
        
        try:
            # Check breaches
            url = f"{self.hibp_email_api}/breachedaccount/{quote(email)}"
            headers = self.headers.copy()
            if api_key:
                headers['hibp-api-key'] = api_key
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result['breached'] = True
                result['breaches'] = response.json()
            elif response.status_code == 404:
                result['breached'] = False
            elif response.status_code == 429:
                result['error'] = 'Rate limited - API key recommended'
        
        except Exception as e:
            result['error'] = str(e)
        
        # Check pastes (requires API key)
        if api_key:
            try:
                url = f"{self.hibp_email_api}/pasteaccount/{quote(email)}"
                headers = self.headers.copy()
                headers['hibp-api-key'] = api_key
                
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    result['pastes'] = response.json()
            except:
                pass
        
        return result
    
    def check_password_leak(self, password: str) -> int:
        """Check if password has been leaked using Have I Been Pwned"""
        # Hash password with SHA-1
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        try:
            url = f"{self.hibp_api}/range/{prefix}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                hashes = response.text.split('\n')
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        return int(count)
        except:
            pass
        
        return 0
    
    def find_employee_repositories(self, employee: Dict) -> List[Dict]:
        """Find personal code repositories for an employee"""
        repos = []
        
        # GitHub repositories
        github_url = employee.get('social_profiles', {}).get('github')
        if github_url:
            username = github_url.split('/')[-1]
            try:
                url = f"https://api.github.com/users/{username}/repos"
                response = requests.get(url, headers=self.headers, timeout=10)
                if response.status_code == 200:
                    for repo in response.json():
                        repos.append({
                            'name': repo.get('name'),
                            'full_name': repo.get('full_name'),
                            'url': repo.get('html_url'),
                            'description': repo.get('description'),
                            'language': repo.get('language'),
                            'private': repo.get('private'),
                            'platform': 'GitHub'
                        })
            except:
                pass
        
        # GitLab repositories
        gitlab_url = employee.get('social_profiles', {}).get('gitlab')
        if gitlab_url:
            username = gitlab_url.split('/')[-1]
            try:
                url = f"https://gitlab.com/api/v4/users/{username}/projects"
                response = requests.get(url, headers=self.headers, timeout=10)
                if response.status_code == 200:
                    for repo in response.json():
                        repos.append({
                            'name': repo.get('name'),
                            'url': repo.get('web_url'),
                            'description': repo.get('description'),
                            'platform': 'GitLab'
                        })
            except:
                pass
        
        return repos
    
    def analyze_company(self, company: str) -> Dict:
        """Comprehensive company analysis"""
        results = {
            'company': company,
            'employees': [],
            'leaked_credentials': [],
            'repositories': []
        }
        
        # Discover employees from multiple sources
        print(f"  [*] Discovering employees from GitHub...")
        github_employees = self._discover_from_github(company)
        results['employees'].extend(github_employees)
        
        print(f"  [*] Discovering employees from GitLab...")
        gitlab_employees = self._discover_from_gitlab(company)
        results['employees'].extend(gitlab_employees)
        
        print(f"  [*] Discovering employees from website...")
        website_employees = self._discover_from_website(company)
        results['employees'].extend(website_employees)

        print(f"  [*] LinkedIn public pivots...")
        results['linkedin_pivots'] = self._discover_from_linkedin(company)
        
        # Remove duplicates
        seen = set()
        unique_employees = []
        for emp in results['employees']:
            key = emp.get('email') or emp.get('name')
            if key and key not in seen:
                seen.add(key)
                unique_employees.append(emp)
        results['employees'] = unique_employees
        
        # Find personal emails and check for leaks
        print(f"  [*] Checking for leaked credentials...")
        for employee in results['employees']:
            # Get personal emails
            personal_emails = self.find_personal_emails(employee)
            
            # Check work email if available
            work_email = employee.get('email')
            if work_email:
                leak_check = self.check_leaked_credentials(work_email)
                if leak_check.get('breached'):
                    results['leaked_credentials'].append({
                        'employee': employee.get('name'),
                        'email': work_email,
                        'breaches': leak_check.get('breaches', []),
                        'type': 'work'
                    })
            
            # Check personal emails
            for email in personal_emails[:3]:  # Limit to 3 per employee
                leak_check = self.check_leaked_credentials(email)
                if leak_check.get('breached'):
                    results['leaked_credentials'].append({
                        'employee': employee.get('name'),
                        'email': email,
                        'breaches': leak_check.get('breaches', []),
                        'type': 'personal'
                    })
        
        # Find repositories
        print(f"  [*] Finding employee repositories...")
        for employee in results['employees']:
            repos = self.find_employee_repositories(employee)
            if repos:
                results['repositories'].extend(repos)
        
        return results

